//! Reads the configuration file and creates a global [Config] object. Manages default values and errors
use std::fs;
use std::io::Error as IoError;

use log::warn;
use serde::{Deserialize, Serialize};
use toml;

#[derive(Serialize, Deserialize, Debug)]
/// Represents the FTP settings
struct ConfigTomlFtp {
    welcome_message: Option<String>,
    help_message: Option<String>,
    ftp_port: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
/// Represents the Honeyney settings
struct ConfigTomlHoneynet {
    id: Option<i32>,
    token: Option<String>,
    url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
/// Represents the VirusTotal settings
struct ConfigTomlVirusTotal {
    token: Option<String>,
    hash_url: Option<String>,
    result_url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
/// Represents the login settings
struct ConfigTomlLogin {
    number_of_tries_before_success: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
/// Represents the file management settings
struct ConfigTomlFileManagement {
    can_be_downloaded: Option<bool>,
    file_upload_real: Option<bool>,
    file_upload_limit: Option<i32>,
    file_size_limit_in_gb: Option<i32>,
    base_save_path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
/// Represents the queue settings
struct ConfigTomlQueue {
    interval: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
/// Represents the full config settings
struct ConfigToml {
    database: Option<ConfigTomlDatabase>,
    application: Option<ConfigTomlApp>,
    virustotal: Option<ConfigTomlVirusTotal>,
    queue: Option<ConfigTomlQueue>,
    login: Option<ConfigTomlLogin>,
    file_management: Option<ConfigTomlFileManagement>,
    ftp: Option<ConfigTomlFtp>,
    honeynet: Option<ConfigTomlHoneynet>,
}

#[derive(Serialize, Deserialize, Debug)]
/// Represents the base application settings
struct ConfigTomlApp {
    version: Option<String>,
    max_concurrent_users: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
/// Represents the database settings
struct ConfigTomlDatabase {
    username: Option<String>,
    password: Option<String>,
    context: Option<String>,
    url: Option<String>,
    database_name: Option<String>,
}

#[derive(Debug)]
/// Represents the full configuration
pub struct Config {
    pub version: String,
    pub max_concurrent_users: i32,
    pub db_url: String,
    pub db_username: String,
    pub db_password: String,
    pub db_context: String,
    pub db_database_name: String,
    pub virus_total_token: String,
    pub virus_total_hash_url: String,
    pub virus_total_result_url: String,
    pub number_of_tries_before_success: i32,
    pub interval: u64,
    pub file_upload_real: bool,
    pub can_be_downloaded: bool,
    pub file_upload_limit: i32,
    pub file_size_limit_in_gb: i32,
    pub base_save_path: String,
    pub ftp_welcome_message: String,
    pub ftp_help_message: String,
    pub ftp_port: i32,
    pub honeynet_id: i32,
    pub honeynet_token: String,
    pub honeynet_url: String,
}

/// Creates a config with [Config::new] and the default file name 'application.toml'.
pub fn get_config() -> Config {
    Config::new("application.toml")
}

impl Config {
    /// Searches for a file in the base path of the application and tries
    /// to parse it to a valid [Config].
    ///
    /// If the file or specific values are missing or invalid, they will be replaced with default
    /// values.
    /// * `location` - Name of the file that is searched for
    pub fn new(location: &str) -> Self {
        let config_filepaths: [&str; 1] = [location];

        let mut content: String = "".to_owned();

        for filepath in config_filepaths {
            let result: Result<String, IoError> = fs::read_to_string(filepath);

            if let Ok(..) = result {
                content = result.unwrap();
                break;
            }
        }

        let config_toml: ConfigToml = toml::from_str(&content).unwrap_or_else(|_| {
            warn!(
                "Configuration setup: Failed to create ConfigToml Object out of config file. \
                Check if the file exists in the given directory and is formatted correctly!"
            );
            ConfigToml {
                database: None,
                application: None,
                queue: None,
                virustotal: None,
                login: None,
                file_management: None,
                ftp: None,
                honeynet: None,
            }
        });

        let (username, password, url, context, database_name): (
            String,
            String,
            String,
            String,
            String,
        ) = match config_toml.database {
            Some(database) => {
                let db_username: String = database.username.unwrap_or_else(|| {
                    warn!("Configuration setup: Missing field username in table database.");
                    "unknown".to_owned()
                });

                let db_password: String = database.password.unwrap_or_else(|| {
                    warn!("Configuration setup: Missing field password in table database.");
                    "unknown".to_owned()
                });

                let db_url: String = database.url.unwrap_or_else(|| {
                    warn!("Configuration setup: Missing field url in table database.");
                    "unknown".to_owned()
                });

                let db_context: String = database.context.unwrap_or_else(|| {
                    warn!("Configuration setup: Missing field context in table database.");
                    "unknown".to_owned()
                });

                let db_database_name: String = database.database_name.unwrap_or_else(|| {
                    warn!("Configuration setup: Missing field context in table database.");
                    "unknown".to_owned()
                });

                (
                    db_username,
                    db_password,
                    db_url,
                    db_context,
                    db_database_name,
                )
            }
            None => {
                warn!("Configuration setup: Missing database data.");
                (
                    "unknown".to_owned(),
                    "unknown".to_owned(),
                    "unknown".to_owned(),
                    "unknown".to_owned(),
                    "unknown".to_owned(),
                )
            }
        };

        let (version, max_concurrent_users): (String, i32) = match config_toml.application {
            Some(app) => {
                let version = app.version.unwrap_or_else(|| {
                    warn!("Configuration setup: Missing field version in application data.");
                    "unknown".to_owned()
                });
                let max_concurrent_users = app.max_concurrent_users.unwrap_or_else(|| {
                    warn!("Configuration setup: Missing field max_concurrent_users in application data.");
                    25.to_owned()
                });
                (version, max_concurrent_users)
            }
            None => {
                warn!("Configuration setup: Missing application data.");
                ("unknown".to_owned(), 25.to_owned())
            }
        };

        let (honeynet_id, honeynet_token, honeynet_url): (i32, String, String) =
            match config_toml.honeynet {
                Some(honeynet) => {
                    let honeynet_id = honeynet.id.unwrap_or_else(|| {
                        warn!("Configuration setup: Missing field id in honeynet data.");
                        1.to_owned()
                    });

                    let honeynet_token = honeynet.token.unwrap_or_else(|| {
                        warn!("Configuration setup: Missing field token in honeynet data.");
                        "invalid_token".to_owned()
                    });

                    let honeynet_url = honeynet.url.unwrap_or_else(|| {
                        warn!("Configuration setup: Missing field url in honeynet data.");
                        "invalid_url".to_owned()
                    });
                    (honeynet_id, honeynet_token, honeynet_url)
                }
                None => {
                    warn!("Configuration setup: Missing ftp data.");
                    (
                        1.to_owned(),
                        "invalid_token".to_owned(),
                        "invalid_url".to_owned(),
                    )
                }
            };

        let (ftp_welcome_message, ftp_help_message, ftp_port): (String, String, i32) =
            match config_toml.ftp {
                Some(ftp) => {
                    let ftp_welcome_message = ftp.welcome_message.unwrap_or_else(|| {
                        warn!("Configuration setup: Missing field welcome_message in ftp data.");
                        "invalid_message".to_owned()
                    });

                    let ftp_help_message = ftp.help_message.unwrap_or_else(|| {
                        warn!("Configuration setup: Missing field help_message in ftp data.");
                        "invalid_message".to_owned()
                    });

                    let ftp_port = ftp.ftp_port.unwrap_or_else(|| {
                        warn!("Configuration setup: Missing field port in ftp data.");
                        8080.to_owned()
                    });
                    (ftp_welcome_message, ftp_help_message, ftp_port)
                }
                None => {
                    warn!("Configuration setup: Missing ftp data.");
                    (
                        "invalid_message".to_owned(),
                        "invalid_message".to_owned(),
                        8080.to_owned(),
                    )
                }
            };

        let (virus_total_token, virus_total_hash_url, virus_total_result_url): (
            String,
            String,
            String,
        ) = match config_toml.virustotal {
            Some(app) => {
                let virus_total_token = app.token.unwrap_or_else(|| {
                    warn!("Configuration setup: Missing field token in virustotal data.");
                    "unknown".to_owned()
                });

                let virus_total_hash_url = app.hash_url.unwrap_or_else(|| {
                    warn!("Configuration setup: Missing field hash_url in virustotal data.");
                    "invalid_url".to_owned()
                });

                let virus_total_result_url = app.result_url.unwrap_or_else(|| {
                    warn!("Configuration setup: Missing field result_url in virustotal data.");
                    "invalid_url".to_owned()
                });
                (
                    virus_total_token,
                    virus_total_hash_url,
                    virus_total_result_url,
                )
            }
            None => {
                warn!("Configuration setup: Missing virustotal data.");
                (
                    "unknown".to_owned(),
                    "invalid_url".to_owned(),
                    "invalid_url".to_owned(),
                )
            }
        };

        let number_of_tries_before_success: i32 = match config_toml.login {
            Some(app) => app.number_of_tries_before_success.unwrap_or_else(|| {
                warn!("Configuration setup: Missing field number_of_tries_before_success in login data.");
                7.to_owned()
            }),
            None => {
                warn!("Configuration setup: Missing login data.");
                7.to_owned()
            }
        };

        let interval: u64 = match config_toml.queue {
            Some(app) => app.interval.unwrap_or_else(|| {
                warn!("Configuration setup: Missing field interval in queue data.");
                5.to_owned()
            }),
            None => {
                warn!("Configuration setup: Missing queue data.");
                5.to_owned()
            }
        };

        let (
            file_upload_real,
            can_be_downloaded,
            file_upload_limit,
            file_size_limit_in_gb,
            base_save_path,
        ): (bool, bool, i32, i32, String) = match config_toml.file_management {
            Some(file_management) => {
                let file_upload_real: bool = file_management.file_upload_real.unwrap_or_else(|| {
                    warn!("Configuration setup: Missing field file_upload_real in file_management data.");
                    false.to_owned()
                });

                let can_be_downloaded: bool =
                    file_management.can_be_downloaded.unwrap_or_else(|| {
                        warn!("Configuration setup: Missing field can_be_downloaded in file_management data.");
                        false.to_owned()
                    });
                let file_upload_limit: i32 =
                    file_management.file_upload_limit.unwrap_or_else(|| {
                        warn!("Configuration setup: Missing field file_upload_limit in file_management data.");
                        10.to_owned()
                    });
                let file_size_limit_in_gb: i32 =
                    file_management.file_size_limit_in_gb.unwrap_or_else(|| {
                        warn!("Configuration setup: Missing field file_size_limit_in_gb in file_management data.");
                        10.to_owned()
                    });
                let base_save_path: String =
                    file_management.base_save_path.unwrap_or_else(|| {
                        warn!("Configuration setup: Missing field base_save_path in file_management data.");
                        "invalid".to_owned()
                    });

                (
                    file_upload_real,
                    can_be_downloaded,
                    file_upload_limit,
                    file_size_limit_in_gb,
                    base_save_path,
                )
            }
            None => {
                warn!("Configuration setup: Missing file_management data.");
                (
                    false.to_owned(),
                    false.to_owned(),
                    10.to_owned(),
                    10.to_owned(),
                    "invalid".to_owned(),
                )
            }
        };
        Config {
            version,
            max_concurrent_users,
            virus_total_token,
            virus_total_result_url,
            virus_total_hash_url,
            number_of_tries_before_success,
            interval,
            file_upload_real,
            can_be_downloaded,
            file_upload_limit,
            file_size_limit_in_gb,
            base_save_path,
            db_url: url,
            db_username: username,
            db_password: password,
            db_context: context,
            db_database_name: database_name,
            ftp_help_message,
            ftp_welcome_message,
            ftp_port,
            honeynet_token,
            honeynet_id,
            honeynet_url,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::configuration::config::Config;

    #[test]
    fn invalid_config_path() {
        let path = "invalid.toml";
        let config = Config::new(path);
        assert_eq!(config.db_database_name, "unknown");
        assert_eq!(config.db_context, "unknown");
        assert_eq!(config.db_username, "unknown");
        assert_eq!(config.db_password, "unknown");
        assert_eq!(config.db_url, "unknown");
        assert_eq!(config.version, "unknown");
        assert_eq!(config.number_of_tries_before_success, 7);
        assert_eq!(config.interval, 5);
        assert!(!config.can_be_downloaded);
        assert!(!config.file_upload_real);
        assert_eq!(config.max_concurrent_users, 25);
        assert_eq!(config.file_upload_limit, 10);
        assert_eq!(config.file_size_limit_in_gb, 10);
        assert_eq!(config.base_save_path, "invalid");
        assert_eq!(config.virus_total_token, "unknown");
        assert_eq!(config.virus_total_hash_url, "invalid_url");
        assert_eq!(config.virus_total_result_url, "invalid_url");
        assert_eq!(config.ftp_port, 8080);
        assert_eq!(config.ftp_welcome_message, "invalid_message");
        assert_eq!(config.ftp_help_message, "invalid_message");
        assert_eq!(config.honeynet_url, "invalid_url");
        assert_eq!(config.honeynet_token, "invalid_token");
        assert_eq!(config.honeynet_id, 1);
    }

    #[test]
    fn valid_config_path_and_values() {
        let path = "application-test.toml";
        let config = Config::new(path);
        assert_eq!(config.db_database_name, "ftp_db");
        assert_eq!(config.db_context, "mysql");
        assert_eq!(config.db_username, "testUsername");
        assert_eq!(config.db_password, "testPW");
        assert_eq!(config.db_url, "localhost:1234");
        assert_eq!(config.version, "0.0.0-testing");
        assert_eq!(config.virus_total_token, "test-token");
        assert_eq!(config.virus_total_hash_url, "test_url_hash");
        assert_eq!(config.virus_total_result_url, "test_url_result");
        assert_eq!(config.number_of_tries_before_success, 2);
        assert_eq!(config.interval, 1);
        assert!(config.can_be_downloaded);
        assert!(config.file_upload_real);
        assert_eq!(config.file_upload_limit, 5);
        assert_eq!(config.file_size_limit_in_gb, 5);
        assert_eq!(config.base_save_path, "/test/path");
        assert_eq!(config.ftp_port, 1111);
        assert_eq!(config.ftp_welcome_message, "welcome_msg");
        assert_eq!(config.ftp_help_message, "help_msg");
        assert_eq!(config.honeynet_url, "honey_url");
        assert_eq!(config.honeynet_token, "honey_token");
        assert_eq!(config.honeynet_id, 2222);
    }
}
