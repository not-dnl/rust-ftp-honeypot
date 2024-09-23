//! Holds information about the current Client

use tokio::net::TcpSocket;

use crate::database::models::attacker;

/// Holds information about the current [Client], the current Attacker
pub struct Client {
    pub username: String,
    pub password: String,
    pub model: Option<attacker::Model>,
    pub ip: String,
    pub data_socket: Option<TcpSocket>,
    pub data_addr: Option<String>,
}
