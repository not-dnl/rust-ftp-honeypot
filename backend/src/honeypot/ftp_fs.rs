//! FTP related file system handling functions

use std::ops::Add;
use std::path::Path;

use log::info;
use rand::distributions::Alphanumeric;
use rand::Rng;
use regex::Regex;
use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::configuration::config::get_config;
#[allow(unused_imports)]
use crate::configuration::config::Config;
use crate::database::models::attacker::Model;
use crate::database::service::DatabaseImplementation;
#[allow(unused_imports)]
use crate::filesystem::ftp_fs::FtpFileSystem;
use crate::honeypot::client::Client;
use crate::honeypot::ftp::{Request, StatusCode};
use crate::honeypot::ftp_helper::{deny_access, send_response};

/// Returns the TCP data stream used to exchange data between the client and the server.
///
/// * `client`   - The current [Client] struct.
async fn get_data_tcp(client: &mut Client) -> TcpStream {
    client
        .data_socket
        .take()
        .unwrap()
        .connect(client.data_addr.take().unwrap().parse().unwrap())
        .await
        .unwrap()
}

/// Takes the current base path from the [Config] and appends the id of the current [Model] along
/// with a [String] and returns the result.
///
/// * `model`    - The current [Model].
/// * `append`   - The [String] to append.
fn get_real_file_path(model: &mut Model, append: String) -> String {
    get_config()
        .base_save_path
        .add(format!("/{}/", model.id.to_string().as_str()).as_str())
        .add(append.as_str())
}

/// Handles the FTP CWD packet.
///
/// If the [FtpFileSystem] knows the path to switch to the current path is updated and the client
/// gets a successful message. Otherwise an error is sent to the client.
///
/// * `stream`   - The TCP stream used to communicate with the client.
/// * `client`   - The current [Client] struct.
/// * `request`  - The [Request] used to handle the argument.
pub async fn cwd(stream: &mut TcpStream, client: &mut Client, request: &Request) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else {
        let model = client.model.as_mut().unwrap();
        let can_cwd = model
            .file_system
            .as_mut()
            .expect("Filesystem not set!")
            .cd_as_str(request.argument.as_str());

        info!(
            "Attacker: {}, attempted to change directory to: {}",
            client.username,
            request.argument.as_str()
        );

        return if !can_cwd {
            if !send_response(
                stream,
                StatusCode::DirectoryCreationFailed,
                "Failed to change directory.",
            )
            .await
            {
                return false;
            }

            true
        } else {
            if !send_response(
                stream,
                StatusCode::RequestedFileActionOkayCompleted,
                "Directory successfully changed.",
            )
            .await
            {
                return false;
            }

            true
        };
    }

    true
}

/// Handles the FTP STOR packet.
///
/// First another TCP connection is established to transfer the data over the new data stream.
/// The client is informed about that and the upload can begin.
/// A random filename is stored on the systems filesystem and the data from the TCP stream is saved
/// to the system. The TCP stream is then terminated. After that the file's metadata is also stored
/// to the [FtpFileSystem] and if configured the file is deleted again from the system. Finally
/// the client is told about the termination of the TCP connection.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `client`   - The current [Client] struct.
/// * `db`       - The [DatabaseImplementation]
/// * `request`  - The [Request] used to handle the argument.
pub async fn stor(
    stream: &mut TcpStream,
    client: &mut Client,
    db: &DatabaseImplementation,
    request: &Request,
) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else {
        let mut tcp = get_data_tcp(client).await;

        if !send_response(stream, StatusCode::FileStatusOkay, "Ready to receive data").await {
            return false;
        }

        let model = client.model.as_mut().unwrap();

        let fake_path = Path::new(request.argument.as_str());

        let random_filename: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();

        let real_path = get_real_file_path(model, random_filename);

        let file_path_real = Path::new(real_path.as_str());

        let mut file = File::create(&file_path_real).await.unwrap();

        let mut buffer = [0; 1024];
        loop {
            let bytes_read = tcp.read(&mut buffer).await.unwrap();
            if bytes_read == 0 {
                break;
            }

            file.write_all(&buffer[..bytes_read]).await.unwrap();
        }

        let contents = fs::read(&real_path).await;

        let hash = sha256::digest(contents.unwrap().as_slice());

        tcp.shutdown().await.unwrap();

        model
            .file_system
            .as_mut()
            .expect("Filesystem not set!")
            .save_file(
                db,
                model.id,
                file_path_real.to_str().unwrap(),
                fake_path.to_str().unwrap(),
                file_path_real.metadata().unwrap().len() as i64,
                hash,
            )
            .await;

        info!(
            "Attacker: {} uploaded File: {:?}",
            client.username,
            fake_path.to_str()
        );

        if !get_config().file_upload_real {
            fs::remove_file(file_path_real)
                .await
                .expect("Failed removing the file!");
        }

        if !send_response(
            stream,
            StatusCode::ClosingDataConnection,
            "Transfer complete.",
        )
        .await
        {
            return false;
        }
    }

    true
}

/// Handles the FTP MKD packet.
///
/// The [FtpFileSystem] first checks if the directory can be created. When possible and new directory
/// is created and the client is informed about the successful operation. If not an error is sent
/// to the client. If configured the directory is also created on the system itself and not only
/// on the [FtpFileSystem].
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `client`   - The current [Client] struct.
/// * `db`       - The [DatabaseImplementation]
/// * `request`  - The [Request] used to handle the argument.
pub async fn mkd(
    stream: &mut TcpStream,
    client: &mut Client,
    db: &DatabaseImplementation,
    request: &Request,
) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else {
        let mut new_dir = request.argument.to_string();

        let model = client.model.as_mut().unwrap();
        let success = model
            .file_system
            .as_mut()
            .expect("Filesystem not set!")
            .save_dir(db, model.id, new_dir.as_str())
            .await;

        if success {
            new_dir = get_real_file_path(model, new_dir);

            info!(
                "Attacker: {} created a new dir: {}",
                client.username, new_dir
            );

            if get_config().file_upload_real {
                let path = Path::new(&new_dir);

                if !path.exists() {
                    fs::create_dir_all(path)
                        .await
                        .expect("Could not create directory");
                }
            }

            if !send_response(
                stream,
                StatusCode::PathnameAvailable,
                "Create directory operation successful.",
            )
            .await
            {
                return false;
            }
        } else if !send_response(
            stream,
            StatusCode::DirectoryCreationFailed,
            "Create directory operation failed.",
        )
        .await
        {
            return false;
        }
    }
    true
}

/// Handles the FTP PWD packet.
///
/// The [FtpFileSystem] returns the current path, which is then sent to the client.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `client`   - The current [Client] struct.
pub async fn pwd(stream: &mut TcpStream, client: &mut Client) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else {
        let model = client.model.as_mut().unwrap();
        let current_path = format!(
            "/{}",
            model
                .file_system
                .as_mut()
                .expect("Filesystem not set!")
                .path
                .join("/")
        );

        info!("Attacker: {} used PWD", client.username);

        if !send_response(
            stream,
            StatusCode::PathnameAvailable,
            format!("\"{}\" is the current directory", current_path).as_str(),
        )
        .await
        {
            return false;
        }
    }

    true
}

/// Handles the FTP LIST packet.
///
/// The [FtpFileSystem] returns the list of files currently listed within the current directory.
/// If a argument to a valid path is given the [FtpFileSystem] returns the files within the
/// given directory. The `-a` argument is also handled and returns all files when the client requests
/// them.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `client`   - The current [Client] struct.
/// * `request`  - The [Request] used to handle the argument.
pub async fn list(stream: &mut TcpStream, client: &mut Client, request: &Request) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else {
        let model = client.model.as_mut().unwrap();
        let mut dir_list = model
            .file_system
            .as_mut()
            .expect("Filesystem not set!")
            .ls_extended_information(model.id);

        let dir_to_ls_into = request.argument.to_string();

        if dir_to_ls_into != "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" {
            dir_list = model
                .file_system
                .as_mut()
                .expect("Filesystem not set!")
                .ls_extended_information_with_str(model.id, dir_to_ls_into.as_str())
                .unwrap_or("".to_string());
        }

        let re = Regex::new(r"-.*a.*").unwrap();
        if re.is_match(dir_to_ls_into.as_str()) {
            dir_list = model
                .file_system
                .as_mut()
                .expect("Filesystem not set!")
                .ls_minus_a_extended_information(model.id);
        }

        if !send_response(
            stream,
            StatusCode::FileStatusOkay,
            "Here comes the directory listing.",
        )
        .await
        {
            return false;
        }

        let mut tcp = get_data_tcp(client).await;

        if dir_list.is_empty() {
            tcp.write_all("".as_bytes())
                .await
                .expect("Panicked during write_all!!");
        } else {
            tcp.write_all(format!("{}\r\n", dir_list).as_bytes())
                .await
                .expect("Panicked during write_all!!");
        }

        info!(
            "Attacker: {} used ls with the following argument: {}",
            client.username, dir_to_ls_into
        );

        if !send_response(
            stream,
            StatusCode::ClosingDataConnection,
            "Directory send OK.",
        )
        .await
        {
            return false;
        }
    }

    true
}

/// Handles the FTP DELE packet.
///
/// The [FtpFileSystem] returns the path on the system to delete first. Then it attempts to delete
/// the file. If the file exists it also gets removed from the actual system. Otherwise an error
/// is sent to the client.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `client`   - The current [Client] struct.
/// * `db`       - The [DatabaseImplementation]
/// * `request`  - The [Request] used to handle the argument.
pub async fn dele(
    stream: &mut TcpStream,
    client: &mut Client,
    db: &DatabaseImplementation,
    request: &Request,
) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else {
        let file_to_delete = request.argument.to_string();

        let model = client.model.as_mut().unwrap();

        let real_file_to_delete = model
            .file_system
            .as_mut()
            .expect("Filesystem not set!")
            .get_physical_file_path(db, file_to_delete.as_str())
            .await;

        let success = model
            .file_system
            .as_mut()
            .expect("Filesystem not set!")
            .rm_file(db, model.id, file_to_delete.as_str())
            .await;

        info!(
            "Attacker: {} attempted to delete: {}",
            client.username, file_to_delete
        );

        if success {
            if get_config().file_upload_real {
                fs::remove_file(real_file_to_delete.1.unwrap())
                    .await
                    .expect("Could not delete file");
            }

            if !send_response(
                stream,
                StatusCode::RequestedFileActionOkayCompleted,
                "File removed.",
            )
            .await
            {
                return false;
            }
        } else if !send_response(
            stream,
            StatusCode::DirectoryCreationFailed,
            "File not removed.",
        )
        .await
        {
            return false;
        }
    }
    true
}

/// Handles the FTP RETR packet.
///
/// First a new TCP data connection is created. The [FtpFileSystem] returns the actual path of the
/// requested file from the systems file system. If the file doesn't exist an error is sent to the
/// client. Otherwise the client is informed about the new TCP data connection. Finally the file
/// is sent to the client on the newly established TCP connection. Additionally if configured the
/// server can also sent a fake file to the client. For this random bytes with the size of the selected
/// file are sent to the client over the new TCP data connection.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `client`   - The current [Client] struct.
/// * `db`       - The [DatabaseImplementation]
/// * `request`  - The [Request] used to handle the argument.
pub async fn retr(
    stream: &mut TcpStream,
    client: &mut Client,
    db: &DatabaseImplementation,
    request: &Request,
) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else {
        let model = client.model.as_mut().unwrap();

        let mut tcp = client
            .data_socket
            .take()
            .unwrap()
            .connect(client.data_addr.take().unwrap().parse().unwrap())
            .await
            .unwrap();

        let physical_path = model
            .file_system
            .as_mut()
            .expect("Filesystem not set!")
            .get_physical_file_path(db, request.argument.as_str())
            .await;

        if physical_path.1.is_none() {
            if !send_response(stream, StatusCode::DirectoryCreationFailed, "Failed").await {
                return false;
            }

            return true;
        }

        if !send_response(stream, StatusCode::FileStatusOkay, "Sending data").await {
            return false;
        }

        let mut file = File::open(physical_path.1.as_ref().unwrap())
            .await
            .expect("Failed to open File!");

        let mut buf = vec![0; 1024];
        loop {
            let n = file.read(&mut buf).await.unwrap();
            if n > 0 {
                tcp.write_all(&buf[..n])
                    .await
                    .expect("Failed writing all to file!");
            } else {
                break;
            }
        }

        tcp.shutdown().await.unwrap();

        info!(
            "Attacker: {} downloaded File: {:?}",
            client.username,
            physical_path.1.as_ref().unwrap()
        );

        if !physical_path.0 {
            fs::remove_file(physical_path.1.unwrap())
                .await
                .expect("Couldn't remove file!");
        }

        if !send_response(
            stream,
            StatusCode::ClosingDataConnection,
            "Transfer complete.",
        )
        .await
        {
            return false;
        }
    }

    true
}

/// Handles the FTP RMD packet.
///
/// The [FtpFileSystem] attempts to delete the directory requested by the client. Upon success the
/// client is informed about the successful action. Upon failure an error is sent to the client.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `client`   - The current [Client] struct.
/// * `db`       - The [DatabaseImplementation]
/// * `request`  - The [Request] used to handle the argument.
pub async fn rmd(
    stream: &mut TcpStream,
    client: &mut Client,
    db: &DatabaseImplementation,
    request: &Request,
) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else {
        let dir_to_delete = request.argument.to_string();

        let model = client.model.as_mut().unwrap();
        let success = model
            .file_system
            .as_mut()
            .expect("Filesystem not set!")
            .rm_dir(db, model.id, dir_to_delete.as_str())
            .await;

        info!(
            "Attacker: {} attempted to delete directory: {}",
            client.username, dir_to_delete
        );

        if success {
            if !send_response(
                stream,
                StatusCode::RequestedFileActionOkayCompleted,
                "Directory removed.",
            )
            .await
            {
                return false;
            }
        } else if !send_response(
            stream,
            StatusCode::DirectoryCreationFailed,
            "Directory not removed.",
        )
        .await
        {
            return false;
        }
    }
    true
}
