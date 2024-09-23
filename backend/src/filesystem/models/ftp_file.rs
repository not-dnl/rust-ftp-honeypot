//! Represents a file of the fake filesystem.

use serde::{Deserialize, Serialize};

#[derive(
    Serialize,
    Deserialize,
    Clone,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    sea_orm::FromJsonQueryResult,
)]
pub struct FtpFile {
    pub name: String,
    pub size: i64,
    pub file_id: Option<i64>,
    pub timestamp: String,
    pub default_file: Option<String>,
}
