//! FTP related helper functions

use log::{error, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::honeypot::encoder::Encoder;
use crate::honeypot::ftp::{Reply, ReplyMessage, StatusCode};

/// Reads a packet sent by the client over the communication TCP stream.
///
/// Upon successful reading of the packet information about the packet a logged.
/// Upon Error the error is logged.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `buf`      - The buffer holding the packet data.
pub async fn read_packet(stream: &mut TcpStream, buf: &mut [u8]) {
    match stream.read(buf).await {
        Ok(_) => {
            info!("Read packet: {:?}", String::from_utf8_lossy(buf))
        }
        Err(e) => {
            error!("Connection error: {}", e);
        }
    }
}

/// Writes a packet to the client over the TCP connection.
///
/// Upon successful writing of the packet information about the packet a logged.
/// Upon Error the error is logged.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `reply`    - The [Reply] to the client.
pub async fn write_packet(stream: &mut TcpStream, reply: &Reply) -> bool {
    match stream.write(&Encoder::encode(reply).unwrap()).await {
        Ok(_) => {
            info!("Wrote packet: {} OK", reply.code);
            true
        }
        Err(e) => {
            error!("Connection error: {}", e);
            false
        }
    }
}

/// Sends a new response to the client over the TCP connection.
///
/// A new [Reply] is constructed and the `status` and `msg` are set accordingly.
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
/// * `status`   - The current [StatusCode].
/// * `msg`      - The message.
pub async fn send_response(stream: &mut TcpStream, status: StatusCode, msg: &str) -> bool {
    let reply = Reply::new(status, ReplyMessage::Is(String::from(msg)));

    if !write_packet(stream, &reply).await {
        return false;
    }

    true
}

/// Denies access to all FTP commands that require access if the attacker isn't logged in.
///
///
/// * `stream`   - The [TcpStream] used to communicate with the client.
pub async fn deny_access(stream: &mut TcpStream) -> bool {
    let reply = Reply::new(
        StatusCode::NotLoggedIn,
        ReplyMessage::Is(String::from("Please login with USER and PASS.")),
    );

    if !write_packet(stream, &reply).await {
        return false;
    }

    true
}
