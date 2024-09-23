//! FTP related misc handling functions

use log::info;
use tokio::net::{TcpSocket, TcpStream};

use crate::configuration::config::get_config;
use crate::honeypot::client::Client;
use crate::honeypot::ftp::{Request, StatusCode};
use crate::honeypot::ftp_helper::{deny_access, send_response};

/// Handles the FTP MODE packet.
///
/// Only the Stream transfer mode is allowed. All other requests are ignored.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `client`   - The current [Client] struct.
/// * `request`  - The [Request] used to handle the argument.
pub async fn mode(stream: &mut TcpStream, client: &mut Client, request: &Request) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else if request.argument == "S" {
        if !send_response(stream, StatusCode::Okay, "Using Stream transfer mode").await {
            return false;
        }
    } else if !send_response(
        stream,
        StatusCode::CommandNotImplemented,
        "Only Stream transfer-mode supported",
    )
    .await
    {
        return false;
    }

    true
}

/// Handles the FTP HELP packet.
///
/// A help message is sent to the client.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
pub async fn help(stream: &mut TcpStream) -> bool {
    if !send_response(
        stream,
        StatusCode::NotLoggedIn,
        get_config().ftp_help_message.as_str(),
    )
    .await
    {
        return false;
    }

    true
}

/// Handles the FTP NOOP packet.
///
/// As the packet name already dictates, No Operation does nothing.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `client`   - The current [Client] struct.
pub async fn noop(stream: &mut TcpStream, client: &mut Client) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else if !send_response(stream, StatusCode::Okay, "Successfully did nothing").await {
        return false;
    }

    true
}

/// Handles the FTP STRU packet.
///
/// Only the File structure mode is allowed. All other requests are ignored.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `client`   - The current [Client] struct.
/// * `request`  - The [Request] used to handle the argument.
pub async fn stru(stream: &mut TcpStream, client: &mut Client, request: &Request) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else if request.argument != "F" {
        if !send_response(
            stream,
            StatusCode::CommandNotImplemented,
            "Only File structure mode is supported",
        )
        .await
        {
            return false;
        }
    } else if !send_response(stream, StatusCode::Okay, "In File structure mode").await {
        return false;
    }

    true
}

/// Handles the FTP SYST packet.
///
/// Returns information about the OS used. In our case this could be fake, depending on the host
/// that runs this honeypot.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
pub async fn syst(stream: &mut TcpStream, client: &mut Client) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else if !send_response(stream, StatusCode::NameSystemType, "UNIX Type: L8").await {
        return false;
    }

    true
}

/// Handles the FTP PORT packet.
///
/// Creates a new TCP connection as instructed by the client.
/// The PORT request has a parameter in the form of h1,h2,h3,h4,p1,p2
/// Meaning that the client is listening for connections on TCP port p1*256+p2 at
/// IP address h1.h2.h3.h4. The Address is constructed, saved in the current [Client] and sent
/// to the client.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `client`   - The current [Client] struct.
/// * `request`  - The [Request] used to handle the argument.
pub async fn port(stream: &mut TcpStream, client: &mut Client, request: &Request) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else {
        let nums: Vec<&str> = request.argument.split(',').collect();
        let port_one = nums[4].parse::<u16>().unwrap();
        let port_two = nums[5].parse::<u16>().unwrap();

        let port = port_one * 256 + port_two;
        let host = format!(
            "{}{}{}{}{}{}{}",
            nums[0], '.', nums[1], '.', nums[2], '.', nums[3]
        );

        let host_port = format!("{}:{}", host, port);
        info!("New TCP connection: {}", host_port);

        let socket = TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap(); // this fixes not being able to connect from localhost to localhost

        client.data_socket = Some(socket);
        client.data_addr = Some(host_port);

        if !send_response(stream, StatusCode::Okay, "PORT command successful.").await {
            return false;
        }
    }

    true
}

/// Handles the FTP TYPE packet.
///
/// We only allow binary mode. It is possible to also allow other modes like shown in the commented
/// code block, but this wasn't required for our purposes.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `client`   - The current [Client] struct.
/// * `_request` - The [Request] used to handle the argument.
pub async fn fn_type(stream: &mut TcpStream, client: &mut Client, _request: &Request) -> bool {
    if client.model.is_none() {
        if !deny_access(stream).await {
            return false;
        }
    } else {
        // We will always stay in binary mode instead.
        if !send_response(stream, StatusCode::Okay, "Always in binary mode").await {
            return false;
        }

        /*let message;
        let status;

        if request.argument.to_uppercase() == "A" {
            message = "Type set to ASCII";
            status = StatusCode::Okay;
        } else if request.argument.to_uppercase() == "I" {
            message = "Type set to binary";
            status = StatusCode::Okay;
        } else {
            message = "Invalid type";
            status = StatusCode::Error;
        }

        if !send_response(stream, status, message).await {
            return false;
        }*/
    }

    true
}
