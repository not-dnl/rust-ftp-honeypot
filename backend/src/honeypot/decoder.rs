//! Decodes the FTP commands & arguments

use std::borrow::Cow;
use std::str::FromStr;

use crate::honeypot::ftp::{Command, Request};

/// The [Decoder] is used to decode FTP packets to a usable state.
pub struct Decoder {}

impl Decoder {
    /// Decodes a FTP packet to the [Request] which holds the [Command] and message [String].
    ///
    /// Invalid packets kill the connection of the client.
    /// Not supported packets will return the CommandNotImplemented status code later on.
    ///
    /// * `packet` - The FTP packet the client sent.
    pub fn decode(packet: Cow<str>) -> Result<Request, String> {
        let altered_string = packet.replace("\r\n", " ");
        let vector_string: Vec<&str> = altered_string.split(' ').collect();

        if vector_string.len() <= 1 {
            return Err("Got invalid packet! Goodbye!".to_string());
        }

        let command_string = vector_string[0];
        let command_res = Command::from_str(command_string);
        let command = command_res.unwrap_or(Command::NOT_SUPPORTED);

        let argument = vector_string[1].to_string();

        Ok(Request { command, argument })
    }
}

#[cfg(test)]
mod tests {
    use crate::honeypot::decoder::Decoder;
    use crate::honeypot::ftp::Command::USER;

    #[test]
    fn valid_decode() {
        // "USER c\r\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        let packet = [
            85, 83, 69, 82, 32, 99, 13, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];

        let res = Decoder::decode(String::from_utf8_lossy(&packet[..]));

        assert_eq!(res.as_ref().unwrap().argument, "c");
        assert_eq!(res.unwrap().command, USER);
    }

    #[test]
    #[should_panic]
    fn invalid_decode() {
        // random garbage, we can't do anything with broken / invalid packets so we panic
        let packet = [44, 33, 22, 11, 10, 66, 33, 99];

        Decoder::decode(String::from_utf8_lossy(&packet[..])).unwrap();
    }
}
