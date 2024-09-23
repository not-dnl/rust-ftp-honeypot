//! Manages the connection to the DBMS
//!

use log::info;
use sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, DbErr, Statement};

use crate::configuration::config::{get_config, Config};

/// Uses config values found in [Config][crate::configuration::config::Config] to set up a connection
/// * `config_name` - Name of the config file that will be used. If empty will use the default name 'application.toml'
///
///
/// # Config values in use
///  - [URL][crate::configuration::config::Config#structfield.db_url]
///
///  - [Username][crate::configuration::config::Config#structfield.db_username]
///
///  - [Password][crate::configuration::config::Config#structfield.db_password]
///
///  - [Database context][crate::configuration::config::Config#structfield.db_context]
///
///  - [Database name][crate::configuration::config::Config#structfield.db_database_name]
pub(crate) async fn set_up_db(config_name: &str) -> Result<DatabaseConnection, DbErr> {
    info!("Setting up Database Connection ... ");
    let config = if config_name.is_empty() {
        get_config()
    } else {
        Config::new(config_name)
    };

    let db = Database::connect(format!(
        "{}://{}:{}@{}",
        config.db_context, config.db_username, config.db_password, config.db_url
    ))
    .await?;

    let db = match db.get_database_backend() {
        DbBackend::MySql => {
            db.execute(Statement::from_string(
                db.get_database_backend(),
                format!(
                    "CREATE DATABASE IF NOT EXISTS `{}`;",
                    config.db_database_name
                ),
            ))
            .await?;
            let url = format!(
                "{}://{}:{}@{}/{}",
                config.db_context,
                config.db_username,
                config.db_password,
                config.db_url,
                config.db_database_name
            );
            Database::connect(&url).await?
        }
        _ => db,
    };

    Ok(db)
}

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseConnection;
    use sea_orm::DbErr;

    use crate::database::connection::set_up_db;

    #[actix_rt::test]
    async fn invalid_db_connection_string_1() {
        let db: Result<DatabaseConnection, DbErr> = set_up_db("application-test.toml").await;
        assert!(db.is_err())
    }
}
