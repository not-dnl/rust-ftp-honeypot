//! Implementation of the database operations

use async_trait::async_trait;
use chrono::{Duration, Local};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, DeleteResult,
    EntityTrait, ExecResult, ModelTrait, QueryFilter, Schema, Statement,
};

use crate::database::models::attacker_to_credentials::ActiveModel;
use crate::database::models::prelude::{
    Attacker, AttackerToCredentials, Credentials, UploadedFiles,
};
use crate::database::models::uploaded_files::Model;
use crate::database::models::{attacker, attacker_to_credentials, credentials, uploaded_files};
use crate::database::service_trait::DatabaseTrait;

#[cfg(feature = "testing")]
pub struct DatabaseImplementation {
    pub db: DatabaseConnection,
}
#[cfg(not(feature = "testing"))]
#[derive(Clone)]
pub struct DatabaseImplementation {
    pub db: DatabaseConnection,
}

const DB_ERROR_MESSAGE: &str = "Error while executing Database statement: ";

#[async_trait]
impl DatabaseTrait for DatabaseImplementation {
    async fn create_attacker_table(&self) -> Result<ExecResult, DbErr> {
        let builder = self.db.get_database_backend();
        let schema = Schema::new(builder);
        let statement = builder.build(&schema.create_table_from_entity(Attacker));
        let table_create_result = self.db.execute(statement).await;
        return table_create_result;
    }
    async fn update_attacker_table(&self) -> Result<ExecResult, DbErr> {
        let update_statement = Statement::from_string(
            self.db.get_database_backend(),
            vec![
                "ALTER TABLE `Attackers`",
                "CHANGE  updated",
                "updated TIMESTAMP NOT NULL",
                "DEFAULT CURRENT_TIMESTAMP",
                "ON UPDATE CURRENT_TIMESTAMP;",
            ]
            .join(" "),
        );
        let update_table_result = self.db.execute(update_statement).await;
        return update_table_result;
    }
    async fn create_credentials_table(&self) -> Result<ExecResult, DbErr> {
        let builder = self.db.get_database_backend();
        let schema = Schema::new(builder);
        let statement = builder.build(&schema.create_table_from_entity(Credentials));
        let table_create_result = self.db.execute(statement).await;
        return table_create_result;
    }

    async fn create_uploaded_files_table(&self) -> Result<ExecResult, DbErr> {
        let builder = self.db.get_database_backend();
        let schema = Schema::new(builder);
        let statement = builder.build(&schema.create_table_from_entity(UploadedFiles));
        let table_create_result = self.db.execute(statement).await;
        return table_create_result;
    }

    async fn create_attacker_to_credentials_table(&self) -> Result<ExecResult, DbErr> {
        let builder = self.db.get_database_backend();
        let schema = Schema::new(builder);
        let statement = builder.build(&schema.create_table_from_entity(AttackerToCredentials));
        let table_create_result = self.db.execute(statement).await;
        return table_create_result;
    }

    // Attacker operations
    async fn get_attacker_by_id(&self, id: i64) -> Option<attacker::Model> {
        let attacker: Option<attacker::Model> = Attacker::find_by_id(id)
            .one(&self.db)
            .await
            .unwrap_or_else(|_| panic!("{} Could not delete attacker by id!", DB_ERROR_MESSAGE));
        return attacker;
    }

    async fn get_attacker_by_ip(&self, ip: &str) -> Option<attacker::Model> {
        let attacker: Option<attacker::Model> = Attacker::find()
            .filter(attacker::Column::Ip.eq(ip))
            .one(&self.db)
            .await
            .unwrap_or_else(|_| panic!("{} Could not get attacker by ip!", DB_ERROR_MESSAGE));
        return attacker;
    }

    async fn get_files_of_attacker_not_updated_in_one_week(
        &self,
    ) -> Vec<(attacker::Model, Vec<Model>)> {
        let time: chrono::DateTime<Local> = Local::now() - Duration::days(7);

        let result: Vec<(attacker::Model, Vec<Model>)> = attacker::Entity::find()
            .find_with_related(UploadedFiles)
            .filter(attacker::Column::Updated.lt(time))
            .all(&self.db)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} Could not get uploaded files by corresponding attacker updated column!",
                    DB_ERROR_MESSAGE
                )
            });
        return result;
    }

    async fn get_attacker_by_timestamp(&self) -> Vec<attacker::Model> {
        let time: chrono::DateTime<Local> = Local::now() - Duration::days(7);

        let result = Attacker::find()
            .filter(attacker::Column::Updated.lt(time))
            .all(&self.db)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} Could not get attacker by updated column!",
                    DB_ERROR_MESSAGE
                )
            });
        return result;
    }

    async fn delete_attacker_if_not_updated_in_one_week(&self) -> DeleteResult {
        let time: chrono::DateTime<Local> = Local::now() - Duration::days(7);
        let result: DeleteResult = attacker::Entity::delete_many()
            .filter(attacker::Column::Updated.lt(time))
            .exec(&self.db)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} Could not delete attacker by updated column!",
                    DB_ERROR_MESSAGE
                )
            });
        return result;
    }

    async fn update_attacker(&self, attacker: attacker::ActiveModel) -> attacker::ActiveModel {
        let attacker: attacker::ActiveModel = attacker.save(&self.db).await.unwrap_or_else(|e| {
            panic!(
                "{} Could not update attacker by Active Model! {}",
                DB_ERROR_MESSAGE, e
            )
        });
        return attacker;
    }

    async fn delete_attacker(&self, attacker: attacker::ActiveModel) -> DeleteResult {
        let result: DeleteResult = attacker.delete(&self.db).await.unwrap_or_else(|_| {
            panic!(
                "{} Could not delete attacker by Active Model!",
                DB_ERROR_MESSAGE
            )
        });
        return result;
    }
    async fn delete_attacker_by_id(&self, id: i64) -> DeleteResult {
        let result: DeleteResult = attacker::Entity::delete_by_id(id)
            .exec(&self.db)
            .await
            .unwrap_or_else(|_| panic!("{} Could not delete attacker by id!", DB_ERROR_MESSAGE));
        return result;
    }

    // Credentials Operations
    async fn get_credentials_by_id(&self, id: i64) -> Option<credentials::Model> {
        let credentials: Option<credentials::Model> = Credentials::find_by_id(id)
            .one(&self.db)
            .await
            .unwrap_or_else(|_| panic!("{} Could not get credentials by id!", DB_ERROR_MESSAGE));
        return credentials;
    }

    async fn get_credentials_by_username_and_password(
        &self,
        username: &str,
        password: &str,
    ) -> Option<credentials::Model> {
        let credentials: Option<credentials::Model> = Credentials::find()
            .filter(
                credentials::Column::Username
                    .eq(username)
                    .and(credentials::Column::Password.eq(password)),
            )
            .one(&self.db)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} Could not get credentials by username and password!",
                    DB_ERROR_MESSAGE
                )
            });
        return credentials;
    }

    async fn update_credentials(
        &self,
        credentials: credentials::ActiveModel,
    ) -> credentials::ActiveModel {
        let credentials: credentials::ActiveModel =
            credentials.save(&self.db).await.unwrap_or_else(|e| {
                panic!(
                    "{} Could not update credentials by Active Model! {}",
                    DB_ERROR_MESSAGE, e
                )
            });
        return credentials;
    }

    async fn get_file_by_id(&self, id: i64) -> Option<Model> {
        let uploaded_file: Option<Model> = UploadedFiles::find_by_id(id)
            .one(&self.db)
            .await
            .unwrap_or_else(|_| panic!("{} Could not get file by id!", DB_ERROR_MESSAGE));
        return uploaded_file;
    }

    // FileUpload operations
    async fn get_file_by_hash(&self, hash: &String) -> Option<Model> {
        let uploaded_file: Option<Model> = UploadedFiles::find()
            .filter(uploaded_files::Column::Hash.eq(hash))
            .one(&self.db)
            .await
            .unwrap_or_else(|_| panic!("{} Could not get file by hash!", DB_ERROR_MESSAGE));
        return uploaded_file;
    }

    async fn get_files_by_attacker_id(&self, attacker_id: i64) -> Vec<Model> {
        let uploaded_files: Vec<Model> = UploadedFiles::find()
            .filter(uploaded_files::Column::AttackerId.eq(attacker_id))
            .all(&self.db)
            .await
            .unwrap_or_else(|_| panic!("{} Could not get files by Attacker id!", DB_ERROR_MESSAGE));
        return uploaded_files;
    }

    async fn get_files_by_missing_virus_total(&self) -> Vec<Model> {
        let uploaded_files: Vec<Model> = UploadedFiles::find()
            .filter(uploaded_files::Column::VirustotalResult.is_null())
            .all(&self.db)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} Could not update get files by virus total result equals NULL!",
                    DB_ERROR_MESSAGE
                )
            });
        return uploaded_files;
    }

    async fn update_file(&self, file: uploaded_files::ActiveModel) -> uploaded_files::ActiveModel {
        let uploaded_file: uploaded_files::ActiveModel =
            file.save(&self.db).await.unwrap_or_else(|_| {
                panic!(
                    "{} Could not update file by Active Model!",
                    DB_ERROR_MESSAGE
                )
            });
        return uploaded_file;
    }

    async fn delete_file(&self, file: uploaded_files::ActiveModel) -> DeleteResult {
        let result: DeleteResult = file.delete(&self.db).await.unwrap_or_else(|_| {
            panic!(
                "{} Could not delete file by Active Model!",
                DB_ERROR_MESSAGE
            )
        });
        return result;
    }

    async fn delete_files_by_attacker_id(&self, attacker_id: i64) -> DeleteResult {
        let result: DeleteResult = uploaded_files::Entity::delete_many()
            .filter(uploaded_files::Column::AttackerId.eq(attacker_id))
            .exec(&self.db)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} Could not delete files by attacker id!",
                    DB_ERROR_MESSAGE
                )
            });
        return result;
    }

    async fn update_attacker_to_credentials(
        &self,
        attacker_to_credentials: ActiveModel,
    ) -> Result<attacker_to_credentials::Model, DbErr> {
        let attacker_to_credentials = attacker_to_credentials.insert(&self.db).await;
        return attacker_to_credentials;
    }
    async fn get_credentials_from_attacker(
        &self,
        attacker: &attacker::Model,
    ) -> Vec<credentials::Model> {
        let result = attacker
            .find_related(Credentials)
            .all(&self.db)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} Could not get credentials by Active Attacker Model!",
                    DB_ERROR_MESSAGE
                )
            });
        return result;
    }

    async fn get_credentials_by_id_from_attacker(
        &self,
        attacker: &attacker::Model,
        credentials_id: i64,
    ) -> Option<credentials::Model> {
        let result = attacker
            .find_related(Credentials)
            .filter(credentials::Column::Id.eq(credentials_id))
            .one(&self.db)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{} Could not get credentials by id from attacker!",
                    DB_ERROR_MESSAGE
                )
            });
        return result;
    }
}
