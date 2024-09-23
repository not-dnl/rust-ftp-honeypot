//! FTP related access handling functions

use tokio::net::TcpStream;

use crate::database::models::attacker::Model;
use crate::database::service::DatabaseImplementation;
use crate::external_api::file_service::create_json_and_send_request;
#[allow(unused_imports)]
use crate::filesystem::ftp_fs::FtpFileSystem;
use crate::honeypot::client::Client;
use crate::honeypot::ftp::{Request, StatusCode};
use crate::honeypot::ftp_helper::send_response;
use crate::login::login_service;

/// Handles the FTP login logic
///
/// Sends each login attempt to the frontend and checks for valid logins.
///
/// * `username` - The attackers username
/// * `password` - The attackers password
/// * `ip`       - The attackers IP
/// * `db`       - The [DatabaseImplementation]
async fn login(
    username: &str,
    password: &str,
    ip: &str,
    db: &DatabaseImplementation,
) -> Option<Model> {
    create_json_and_send_request(ip, username, password).await;
    login_service::is_login_valid(username, password, ip, db).await
}

/// Handles the FTP USER packet.
///
/// Sends each login attempt to the frontend and checks for valid logins.
/// Currently all usernames are valid.
///
/// * `stream`   - The TCP stream used to communicate with the client.
/// * `client`   - The current [Client] struct.
/// * `request`  - The [Request] used to handle the argument.
pub async fn user(stream: &mut TcpStream, client: &mut Client, request: &Request) -> bool {
    client.username = request.argument.to_string();

    if !send_response(
        stream,
        StatusCode::UserNameOkayNeedPassword,
        "Please specify the password.",
    )
    .await
    {
        return false;
    }

    true
}

/// Handles the FTP ACCT packet.
///
/// ACCT is always Rejected.
pub async fn acct(stream: &mut TcpStream) -> bool {
    if !send_response(stream, StatusCode::NotLoggedIn, "Rejected").await {
        return false;
    }

    true
}

/// Handles the FTP PASS packet.
///
/// Upon a valid login a [Model] is created and the attacker is greeted with a successful
/// login.
/// The [FtpFileSystem] path is set back to it's default state upon a successful login.
///
/// * `stream`   - The TCP stream used to communicate with the client.
/// * `client`   - The current [Client] struct.
/// * `request`  - The [Request] used to handle the argument.
/// * `db`       - The [DatabaseImplementation]
pub async fn pass(
    stream: &mut TcpStream,
    client: &mut Client,
    request: &Request,
    db: &DatabaseImplementation,
) -> bool {
    client.password = request.argument.to_string();
    client.model = login(&client.username, &client.password, &client.ip, db).await;
    if client.model.is_some() {
        if !send_response(stream, StatusCode::UserLoggedInProceed, "Login successful.").await {
            return false;
        }

        let model = client.model.as_mut().unwrap();

        model
            .file_system
            .as_mut()
            .expect("Filesystem not set!")
            .clear_path(db, model.id)
            .await;
    } else if !send_response(stream, StatusCode::NotLoggedIn, "Login incorrect.").await {
        return false;
    }

    true
}

/// Handles the FTP QUIT packet.
///
/// Bye.
pub async fn quit(stream: &mut TcpStream) -> bool {
    if !send_response(stream, StatusCode::UserSuccessfulLogout, "Bye.").await {
        return false;
    }

    false
}
