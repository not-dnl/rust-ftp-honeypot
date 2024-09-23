//! Model of the 'Attacker' table

use chrono::Local;
use sea_orm::entity::prelude::*;

use crate::filesystem::ftp_fs::FtpFileSystem;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "Attackers")]
/// Main model that is used
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i64,
    pub ip: String,
    #[sea_orm(column_name = "loginCount")]
    pub login_count: i32,
    #[sea_orm(column_name = "credentialsId")]
    pub credentials_id: Option<i64>,
    #[sea_orm(column_type = "Timestamp")]
    pub updated: chrono::DateTime<Local>,
    pub file_system: Option<FtpFileSystem>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
/// Represents the relation to other tables
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::credentials::Entity",
        from = "Column::CredentialsId",
        to = "super::credentials::Column::Id",
        on_update = "NoAction",
        on_delete = "NoAction"
    )]
    Credentials,
    #[sea_orm(has_many = "super::uploaded_files::Entity")]
    UploadedFiles,
}

impl Related<super::uploaded_files::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::UploadedFiles.def()
    }
}

impl Related<super::credentials::Entity> for Entity {
    fn to() -> RelationDef {
        super::attacker_to_credentials::Relation::Credentials.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::attacker_to_credentials::Relation::Attacker
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}
