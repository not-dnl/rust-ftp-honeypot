//! Interface of the database operations

use async_trait::async_trait;
use mockall::predicate::*;
use sea_orm::{DbErr, DeleteResult, ExecResult};

use crate::database::models::{attacker, attacker_to_credentials, credentials, uploaded_files};

#[async_trait]
pub trait DatabaseTrait {
    async fn create_attacker_table(&self) -> Result<ExecResult, DbErr>;
    async fn update_attacker_table(&self) -> Result<ExecResult, DbErr>;
    async fn create_credentials_table(&self) -> Result<ExecResult, DbErr>;
    async fn create_uploaded_files_table(&self) -> Result<ExecResult, DbErr>;
    async fn create_attacker_to_credentials_table(&self) -> Result<ExecResult, DbErr>;
    async fn get_attacker_by_id(&self, id: i64) -> Option<attacker::Model>;
    async fn get_attacker_by_ip(&self, ip: &str) -> Option<attacker::Model>;
    async fn get_files_of_attacker_not_updated_in_one_week(
        &self,
    ) -> Vec<(attacker::Model, Vec<uploaded_files::Model>)>;
    async fn get_attacker_by_timestamp(&self) -> Vec<attacker::Model>;
    async fn delete_attacker_if_not_updated_in_one_week(&self) -> DeleteResult;
    async fn update_attacker(&self, attacker: attacker::ActiveModel) -> attacker::ActiveModel;
    async fn delete_attacker(&self, attacker: attacker::ActiveModel) -> DeleteResult;
    async fn delete_attacker_by_id(&self, id: i64) -> DeleteResult;
    async fn get_credentials_by_id(&self, id: i64) -> Option<credentials::Model>;
    async fn get_credentials_by_username_and_password(
        &self,
        username: &str,
        password: &str,
    ) -> Option<credentials::Model>;
    async fn update_credentials(
        &self,
        credentials: credentials::ActiveModel,
    ) -> credentials::ActiveModel;
    async fn get_file_by_id(&self, id: i64) -> Option<uploaded_files::Model>;
    async fn get_file_by_hash(&self, hash: &String) -> Option<uploaded_files::Model>;
    async fn get_files_by_attacker_id(&self, attacker_id: i64) -> Vec<uploaded_files::Model>;
    async fn get_files_by_missing_virus_total(&self) -> Vec<uploaded_files::Model>;
    async fn update_file(&self, file: uploaded_files::ActiveModel) -> uploaded_files::ActiveModel;
    async fn delete_file(&self, file: uploaded_files::ActiveModel) -> DeleteResult;
    async fn delete_files_by_attacker_id(&self, attacker_id: i64) -> DeleteResult;
    async fn update_attacker_to_credentials(
        &self,
        attacker_to_credentials: attacker_to_credentials::ActiveModel,
    ) -> Result<attacker_to_credentials::Model, DbErr>;
    async fn get_credentials_from_attacker(
        &self,
        attacker: &attacker::Model,
    ) -> Vec<credentials::Model>;

    async fn get_credentials_by_id_from_attacker(
        &self,
        attacker: &attacker::Model,
        credentials_id: i64,
    ) -> Option<credentials::Model>;
}
