//! FTP handler that includes the main FTP server-client logic

use std::sync::{Arc, Mutex};

use log::{error, info};
use tokio::net::TcpStream;

use crate::configuration::config::get_config;
use crate::database::service::DatabaseImplementation;
use crate::honeypot::client::Client;
use crate::honeypot::decoder::Decoder;
use crate::honeypot::ftp::{Command, StatusCode};
use crate::honeypot::ftp_access::{acct, pass, quit, user};
use crate::honeypot::ftp_fs::{cwd, dele, list, mkd, pwd, retr, rmd, stor};
use crate::honeypot::ftp_helper::{read_packet, send_response};
use crate::honeypot::ftp_misc::{fn_type, help, mode, noop, port, stru, syst};

/// Handles the main loop and logic of the FTP honeypot.
///
/// The client is first greeted with a welcome message, as long as the `current_users` limit isn't reached.
/// A new [Client] struct is created for each /// new connection to the FTP server.
/// The main loop begins by reading packets and handling them
/// accordingly in their functions. The packets read are decoded by the [Decoder] to handle them.
/// Commands that are not supported are replied to with an error message.
/// Upon an error from the [Decoder] the main loop is broken out of and the connection is terminated.
///
/// * `stream`          - The [TcpStream] used to communicate with the client.
/// * `ip`              - The current IP of the attacker.
/// * `db`              - The [DatabaseImplementation].
/// * `current_users`   - The amount of currently active users, wrapped around a [Arc] [Mutex].
pub async fn handle_connection(
    stream: &mut TcpStream,
    ip: String,
    db: &DatabaseImplementation,
    current_users: Arc<Mutex<i32>>,
) {
    if *current_users.lock().unwrap() >= get_config().max_concurrent_users {
        info!(
            "Max concurrent users reached! Blocking IP: {} with status code 421!",
            ip
        );

        if !send_response(
            stream,
            StatusCode::ServiceNotAvailable,
            "Please come back in 2040 seconds.",
        )
        .await
        {
            return;
        }

        return;
    }

    info!("New connection from: {}", ip);

    *current_users.lock().unwrap() += 1;

    if !send_response(
        stream,
        StatusCode::ServiceReadyForNewUser,
        get_config().ftp_welcome_message.as_str(),
    )
    .await
    {
        return;
    }

    let mut client = Client {
        username: "".to_string(),
        password: "".to_string(),
        model: None,
        ip,
        data_socket: None,
        data_addr: None,
    };

    loop {
        let mut packet: [u8; 32] = [0; 32];
        read_packet(stream, &mut packet).await;

        match &Decoder::decode(String::from_utf8_lossy(&packet[..])) {
            Ok(request) => match request.command {
                Command::USER => {
                    if !user(stream, &mut client, request).await {
                        break;
                    }
                }
                Command::PASS => {
                    if !pass(stream, &mut client, request, db).await {
                        break;
                    }
                }
                Command::ACCT => {
                    if !acct(stream).await {
                        break;
                    }
                }
                Command::SYST => {
                    if !syst(stream, &mut client).await {
                        break;
                    }
                }
                Command::MODE => {
                    if !mode(stream, &mut client, request).await {
                        break;
                    }
                }
                Command::STRU => {
                    if !stru(stream, &mut client, request).await {
                        break;
                    }
                }
                Command::HELP => {
                    if !help(stream).await {
                        break;
                    }
                }
                Command::NOOP => {
                    if !noop(stream, &mut client).await {
                        break;
                    }
                }
                Command::QUIT => {
                    if !quit(stream).await {
                        break;
                    }
                }
                Command::CWD => {
                    if !cwd(stream, &mut client, request).await {
                        break;
                    }
                }
                Command::PORT => {
                    if !port(stream, &mut client, request).await {
                        break;
                    }
                }
                Command::TYPE => {
                    if !fn_type(stream, &mut client, request).await {
                        break;
                    }
                }
                Command::STOR => {
                    if !stor(stream, &mut client, db, request).await {
                        break;
                    }
                }
                Command::MKD => {
                    if !mkd(stream, &mut client, db, request).await {
                        break;
                    }
                }
                Command::PWD => {
                    if !pwd(stream, &mut client).await {
                        break;
                    }
                }
                Command::LIST => {
                    if !list(stream, &mut client, request).await {
                        break;
                    }
                }
                Command::DELE => {
                    if !dele(stream, &mut client, db, request).await {
                        break;
                    }
                }
                Command::RETR => {
                    if !retr(stream, &mut client, db, request).await {
                        break;
                    }
                }
                Command::RMD => {
                    if !rmd(stream, &mut client, db, request).await {
                        break;
                    }
                }
                Command::CDUP => {
                    if !send_response(stream, StatusCode::DirectoryCreationFailed, "Rejected.")
                        .await
                    {
                        break;
                    }
                }
                Command::ALLO => {
                    if !send_response(stream, StatusCode::CommandOkayNotImplemented, "Ignored.")
                        .await
                    {
                        break;
                    }
                }
                Command::STAT => {
                    if !send_response(
                        stream,
                        StatusCode::CommandNotImplementedForParameter,
                        "Rejected.",
                    )
                    .await
                    {
                        break;
                    }
                }
                Command::NOT_SUPPORTED => {
                    if !send_response(
                        stream,
                        StatusCode::CommandNotImplemented,
                        "Command not implemented.",
                    )
                    .await
                    {
                        break;
                    }
                }
            },
            Err(e) => {
                error!("Error: {}", e);
                break;
            }
        }
    }

    *current_users.lock().unwrap() -= 1;
}
