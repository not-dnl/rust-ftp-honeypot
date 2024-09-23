//! FTP related helper structs & enums

use strum_macros::Display;
use strum_macros::EnumString;

#[derive(Clone, Copy, Display)]
/// The FTP StatusCodes used to communicate with the client.
pub enum StatusCode {
    ServiceReadyForNewUser = 220,
    UserNameOkayNeedPassword = 331,
    UserLoggedInProceed = 230,
    NameSystemType = 215,
    RequestedFileActionOkayCompleted = 250,
    CommandNotImplemented = 502,
    NotLoggedIn = 530,
    Okay = 200,
    FileStatusOkay = 150,
    CommandOkayNotImplemented = 202,
    UserSuccessfulLogout = 221,
    PathnameAvailable = 257,
    DirectoryCreationFailed = 550,
    ClosingDataConnection = 226,
    CommandNotImplementedForParameter = 504,
    ServiceNotAvailable = 421,
}

#[allow(dead_code)]
/// The ReplyMessage which holds the message [String].
pub enum ReplyMessage {
    None,
    Is(String),
}

/// The Reply struct which hold [StatusCode] and the [ReplyMessage].
pub struct Reply {
    pub code: StatusCode,
    pub msg: ReplyMessage,
}

impl Reply {
    /// Constructs a new [Reply] object used to communicate with the client.
    pub fn new(code: StatusCode, msg: ReplyMessage) -> Self {
        Reply { code, msg }
    }
}

#[allow(dead_code)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, EnumString)]
/// The FTP [Command] enum which holds all handled commands.
pub enum Command {
    USER,
    PASS,
    ACCT,
    QUIT,
    PORT,
    TYPE,
    MODE,
    STRU,
    RETR,
    STOR,
    SYST,
    CWD,
    NOOP,
    HELP,
    MKD,
    PWD,
    LIST,
    CDUP,
    DELE,
    ALLO,
    RMD,
    STAT,
    #[allow(non_camel_case_types)]
    // RNTO,
    // NLST,
    // STOU,
    // PASV,
    // APPE,
    // REST,
    // RNFR,
    NOT_SUPPORTED,
}

/// The [Request] struct which holds the [Command] and the argument [String] used to communicate with
/// the client.
pub struct Request {
    pub command: Command,
    pub argument: String,
}
