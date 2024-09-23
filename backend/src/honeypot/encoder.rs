//! Encodes the FTP commands & arguments

use std::io::Write;

use crate::honeypot::ftp::{Reply, ReplyMessage};

/// The [Encoder] is used to encode FTP packets to a usable state.
pub struct Encoder {}

impl Encoder {
    /// Encodes a FTP packet to a bytes so it can be sent over the TCP connection
    /// and understood by the client.
    ///
    /// * `reply` - The FTP reply struct that holds the status code and the message.
    pub fn encode(reply: &Reply) -> Result<Vec<u8>, std::io::Error> {
        let mut vec = Vec::new();

        match &reply.msg {
            ReplyMessage::Is(message) => write!(vec, "{} {}\r\n", reply.code as u32, message)?,
            _ => write!(vec, "{}\r\n", reply.code as u32)?, // Just in case, but this wasn't necessary yet.
        }

        Ok(vec)
    }
}

#[cfg(test)]
mod tests {
    use crate::honeypot::encoder::Encoder;
    use crate::honeypot::ftp::{Reply, ReplyMessage, StatusCode};

    #[test]
    fn valid_encode() {
        let reply = Reply::new(StatusCode::Okay, ReplyMessage::Is(String::from("Test")));

        let res = Encoder::encode(&reply).unwrap();

        // "200 Test\r\n"
        assert_eq!(res, [50, 48, 48, 32, 84, 101, 115, 116, 13, 10]);
    }
}
