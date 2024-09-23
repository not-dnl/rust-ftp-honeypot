//! Service that contains login rules and manages logins.

use std::cmp::Ordering;

use log::info;
use sea_orm::ActiveValue::Set;
use sea_orm::{IntoActiveModel, NotSet};

use crate::configuration;
use crate::database::models::attacker::Model;
use crate::database::models::{attacker, attacker_to_credentials, credentials};
use crate::database::service::DatabaseImplementation;
use crate::database::service_trait::DatabaseTrait;
use crate::filesystem::ftp_fs::new_fs_of_attacker;

/// Creates a new attacker and saves value to database table
async fn add_new_attacker(ip: &str, db: &DatabaseImplementation) -> i64 {
    let attacker = attacker::ActiveModel {
        id: NotSet,
        ip: Set(ip.to_string()),
        login_count: Set(1),
        ..Default::default()
    };
    let result = db.update_attacker(attacker).await;
    result.id.unwrap()
}

/// Gets credentials of an attacker
///
/// # If no credentials available
/// - Creates new [credentials::Model] with the given username and password
///
/// - Sets [current login count][credentials::Model#structfield.count] to 1
///
/// - Updates credentials
///
/// # If credentials available
/// - Increments [current login count][credentials::Model#structfield.count]
///
/// - Updates credentials
///
///
async fn get_credentials_and_update_count(
    username: &str,
    password: &str,
    db: &DatabaseImplementation,
) -> credentials::ActiveModel {
    let credentials_optional: Option<credentials::Model> = db
        .get_credentials_by_username_and_password(username, password)
        .await;
    match credentials_optional {
        None => {
            let creds = credentials::ActiveModel {
                id: NotSet,
                username: Set(username.to_string()),
                password: Set(password.to_string()),
                count: Set(1),
            };
            db.update_credentials(creds).await
        }
        Some(mut _credentials) => {
            let mut creds = _credentials.into_active_model();
            creds.count = Set(creds.count.unwrap() + 1);
            db.update_credentials(creds).await
        }
    }
}

/// Updates a given attacker
async fn update_attacker(
    attacker: &Model,
    credentials_id_optional: Option<i64>,
    db: &DatabaseImplementation,
) -> attacker::ActiveModel {
    let mut attacker = attacker.clone().into_active_model();
    if credentials_id_optional.is_some() {
        if attacker.credentials_id.unwrap().is_none() {
            attacker.file_system = Set(Some(new_fs_of_attacker(attacker.id.clone().unwrap())));
        }

        attacker.credentials_id = Set(credentials_id_optional);
    }
    attacker.login_count = Set(attacker.login_count.unwrap() + 1);
    db.update_attacker(attacker).await
}

/// Links an [Attacker][attacker] to the current [Credentials][credentials]
async fn update_credentials_of_attacker(
    attacker_id: i64,
    credentials_id: i64,
    db: &DatabaseImplementation,
) {
    let attacker_to_credentials = attacker_to_credentials::ActiveModel {
        credentials_id: Set(credentials_id),
        attacker_id: Set(attacker_id),
    };
    db.update_attacker_to_credentials(attacker_to_credentials)
        .await
        .expect("Could not update credentials of attacker");
}

/// Checks if an [Attacker][attacker] already tried the given [Credentials][credentials]
///
/// If an [Attacker][attacker] has the permission to login the current credentials will be checked
/// against all credentials the [Attacker][attacker] already tried.
///
/// # If tried already
/// Deny access
///
/// # If not tried already
/// Save the credentials for the [Attacker][attacker] and allow access
///
async fn check_credentials_of_attacker(
    credentials_id: i64,
    db: &DatabaseImplementation,
    attacker: &Model,
    ip: &str,
) -> bool {
    let result = db
        .get_credentials_by_id_from_attacker(attacker, credentials_id)
        .await;
    match result {
        None => {
            info!(
                "Attacker with IP: '{}' did not try the credentials already, accepted.",
                ip
            );
            update_attacker(attacker, Some(credentials_id), db).await;
            true
        }
        Some(_) => {
            info!(
                "Attacker with IP: '{}' already tried the credentials, declined.",
                ip
            );
            update_attacker(attacker, None, db).await;
            false
        }
    }
}

/// Manages the [Attacker][attacker] login
///
/// # Checks if the given IP address is already known
///
/// ## If not known
/// Create a new database entry for the [Attacker][attacker] and deny access.
///
/// ## If known
/// Checks the [login count][credentials::Model#structfield.count] of the [Attacker][attacker] and
/// compares it to the thresholds set in the [Config][configuration::config::Config#structfield.number_of_tries_before_success].
///
/// #### Lesser
/// - updates models
/// - deny access
///
/// #### Equal
/// - updates models
/// - allows access if the attacker has not previously tried the current [Credentials][credentials]
///
/// #### Greater
/// - updates models
/// - If attacker already has credentials:
///     Allows access if the current [Credentials][credentials] match the [Credentials][credentials] of the [Attacker][attacker]
/// -  If attacker has no credentials:
///     Allows access if the [Attacker][attacker] has not previously tried the current [Credentials][credentials]
///
pub async fn is_login_valid(
    username: &str,
    password: &str,
    ip: &str,
    db: &DatabaseImplementation,
) -> Option<Model> {
    let attacker_optional = db.get_attacker_by_ip(ip).await;
    let _login_count: i32 = configuration::config::get_config().number_of_tries_before_success;

    match attacker_optional {
        None => {
            info!(
                "Attacker with IP: '{}' not found. Adding new Attacker and updating tables.",
                ip
            );
            let attacker_id = add_new_attacker(ip, db).await;
            let credentials = get_credentials_and_update_count(username, password, db).await;
            update_credentials_of_attacker(attacker_id, credentials.id.unwrap(), db).await;

            None
        }
        Some(attacker) => match attacker.login_count.cmp(&_login_count) {
            Ordering::Less => {
                info!(
                    "Attacker with IP: '{}' found. Login count ({}) is lower than threshold \
                    ({}). Denying login and updating tables",
                    ip, attacker.login_count, _login_count
                );
                let credentials = get_credentials_and_update_count(username, password, db).await;
                update_attacker(&attacker, None, db).await;
                update_credentials_of_attacker(attacker.id, credentials.id.unwrap(), db).await;

                None
            }
            Ordering::Equal => {
                info!(
                    "Attacker with IP: '{}' found. Login count ({}) is equal to the threshold \
                        ({}). Accepting login if credentials are not declined and updating tables",
                    ip, attacker.login_count, _login_count
                );

                let credentials: credentials::ActiveModel =
                    get_credentials_and_update_count(username, password, db).await;

                check_credentials(db, credentials.id.clone().unwrap(), &attacker, ip).await
            }
            Ordering::Greater => {
                let credentials: credentials::ActiveModel =
                    get_credentials_and_update_count(username, password, db).await;

                match attacker.credentials_id {
                    None => {
                        info!(
                        "Attacker with IP: '{}' found. Login count ({}) is greater than the threshold \
                        ({}). Accepting login if credentials are not declined and updating tables",
                        ip, attacker.login_count, _login_count
                    );
                        check_credentials(db, credentials.id.clone().unwrap(), &attacker, ip).await
                    }
                    Some(_) => {
                        let cur_credentials: credentials::Model = db
                            .get_credentials_by_id(attacker.credentials_id.unwrap())
                            .await
                            .unwrap();
                        update_attacker(&attacker, Some(attacker.credentials_id.unwrap()), db)
                            .await;
                        info!(
                        "Attacker with IP: '{}' found. Login count ({}) is greater than the threshold \
                        ({}). Checking credentials and updating tables. Are credentials equal? {}",
                        ip, attacker.login_count, _login_count,
                        username.eq(&cur_credentials.username) && password.eq(&cur_credentials.password));

                        if username.eq(&cur_credentials.username)
                            && password.eq(&cur_credentials.password)
                        {
                            Some(attacker)
                        } else {
                            None
                        }
                    }
                }
            }
        },
    }
}

async fn check_credentials(
    db: &DatabaseImplementation,
    credentials_id: i64,
    attacker: &Model,
    ip: &str,
) -> Option<Model> {
    if check_credentials_of_attacker(credentials_id, db, attacker, ip).await {
        db.get_attacker_by_ip(ip).await
    } else {
        None
    }
}

#[cfg(test)]
#[cfg(feature = "testing")]
mod test {
    use sea_orm::{DatabaseBackend, DatabaseConnection, MockDatabase, MockExecResult};

    use crate::database::models::{attacker, attacker_to_credentials, credentials};
    use crate::database::service::DatabaseImplementation;
    use crate::filesystem::ftp_fs::new_fs;
    use crate::login::login_service::{get_credentials_and_update_count, is_login_valid};

    #[actix_rt::test]
    async fn test_is_login_valid_attacker_known_1_6() {
        let username = String::from("username");
        let password = String::from("password");
        let ip = String::from("ip");
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 2,
                credentials_id: None,
                updated: Default::default(),
                file_system: None,
            }]])
            .append_query_results([
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 5,
                }],
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 6,
                }],
            ])
            .append_exec_results([MockExecResult {
                last_insert_id: 11,
                rows_affected: 1,
            }])
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 3,
                credentials_id: None,
                updated: Default::default(),
                file_system: None,
            }]])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .append_query_results([[attacker_to_credentials::Model {
                attacker_id: 1,
                credentials_id: 11,
            }]])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .into_connection();

        let res = is_login_valid(&username, &password, &ip, &DatabaseImplementation { db }).await;
        assert!(res.is_none())
    }

    #[actix_rt::test]
    async fn test_is_login_valid_attacker_known_7_with_valid_login_data() {
        let username = String::from("username");
        let password = String::from("password");
        let ip = String::from("ip");
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 7,
                credentials_id: None,
                updated: Default::default(),
                file_system: Some(new_fs()),
            }]])
            .append_query_results([
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 8,
                }],
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 9,
                }],
            ])
            .append_exec_results([MockExecResult {
                last_insert_id: 11,
                rows_affected: 1,
            }])
            .append_query_results([vec![] as Vec<credentials::Model>])
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 8,
                credentials_id: Some(11),
                updated: Default::default(),
                file_system: Some(new_fs()),
            }]])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 8,
                credentials_id: Some(11),
                updated: Default::default(),
                file_system: Some(new_fs()),
            }]])
            .into_connection();

        let res = is_login_valid(&username, &password, &ip, &DatabaseImplementation { db }).await;
        assert!(res.is_some());
        assert_eq!(1, res.clone().unwrap().id);
        assert_eq!(11, res.unwrap().credentials_id.unwrap());
    }

    #[actix_rt::test]
    async fn test_is_login_valid_attacker_known_7_with_invalid_login_data() {
        let username = String::from("username");
        let password = String::from("password");
        let ip = String::from("ip");
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 7,
                credentials_id: None,
                updated: Default::default(),
                file_system: Some(new_fs()),
            }]])
            .append_query_results([
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 8,
                }],
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 9,
                }],
            ])
            .append_exec_results([MockExecResult {
                last_insert_id: 11,
                rows_affected: 1,
            }])
            .append_query_results([[credentials::Model {
                id: 13,
                username: username.clone(),
                password: password.clone(),
                count: 9,
            }]])
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 8,
                credentials_id: Some(11),
                updated: Default::default(),
                file_system: Some(new_fs()),
            }]])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .into_connection();

        let res = is_login_valid(&username, &password, &ip, &DatabaseImplementation { db }).await;
        assert!(res.is_none());
    }

    #[actix_rt::test]
    async fn test_is_login_valid_attacker_known_greater_7_no_fk_valid_login() {
        let username = String::from("username");
        let password = String::from("password");
        let ip = String::from("ip");
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 8,
                credentials_id: None,
                updated: Default::default(),
                file_system: Some(new_fs()),
            }]])
            .append_query_results([
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 8,
                }],
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 9,
                }],
            ])
            .append_exec_results([MockExecResult {
                last_insert_id: 11,
                rows_affected: 1,
            }])
            .append_query_results([vec![] as Vec<credentials::Model>])
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 9,
                credentials_id: Some(11),
                updated: Default::default(),
                file_system: Some(new_fs()),
            }]])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 8,
                credentials_id: Some(11),
                updated: Default::default(),
                file_system: Some(new_fs()),
            }]])
            .into_connection();

        let res = is_login_valid(&username, &password, &ip, &DatabaseImplementation { db }).await;
        assert!(res.is_some());
        assert_eq!(1, res.clone().unwrap().id);
        assert_eq!(11, res.unwrap().credentials_id.unwrap());
    }

    #[actix_rt::test]
    async fn test_is_login_valid_attacker_known_greater_7_no_fk_invalid_login() {
        let username = String::from("username");
        let password = String::from("password");
        let ip = String::from("ip");
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 8,
                credentials_id: None,
                updated: Default::default(),
                file_system: Some(new_fs()),
            }]])
            .append_query_results([
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 8,
                }],
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 9,
                }],
            ])
            .append_exec_results([MockExecResult {
                last_insert_id: 11,
                rows_affected: 1,
            }])
            .append_query_results([[credentials::Model {
                id: 11,
                username: username.clone(),
                password: password.clone(),
                count: 9,
            }]])
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 9,
                credentials_id: Some(11),
                updated: Default::default(),
                file_system: Some(new_fs()),
            }]])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .into_connection();

        let res = is_login_valid(&username, &password, &ip, &DatabaseImplementation { db }).await;
        assert!(res.is_none());
    }

    #[actix_rt::test]
    async fn test_is_login_valid_attacker_known_greater_7_fk_valid_login() {
        let username = String::from("username");
        let password = String::from("password");
        let ip = String::from("ip");
        let db = db_helper(username.clone(), password.clone(), ip.clone());

        let res = is_login_valid(&username, &password, &ip, &DatabaseImplementation { db }).await;
        assert!(res.is_some());
    }

    #[actix_rt::test]
    async fn test_is_login_valid_attacker_known_greater_7_fk_invalid_login() {
        let username = String::from("username");
        let password = String::from("password");
        let ip = String::from("ip");
        let db = db_helper(username.clone(), password.clone(), ip.clone());

        let res = is_login_valid("invalid", &password, &ip, &DatabaseImplementation { db }).await;
        assert!(res.is_none());
    }

    fn db_helper(username: String, password: String, ip: String) -> DatabaseConnection {
        MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 8,
                credentials_id: Some(11),
                updated: Default::default(),
                file_system: Some(new_fs()),
            }]])
            .append_query_results([
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 8,
                }],
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 9,
                }],
            ])
            .append_exec_results([MockExecResult {
                last_insert_id: 11,
                rows_affected: 1,
            }])
            .append_query_results([[credentials::Model {
                id: 11,
                username: username.clone(),
                password: password.clone(),
                count: 9,
            }]])
            .append_query_results([[attacker::Model {
                id: 1,
                ip: ip.clone(),
                login_count: 9,
                credentials_id: Some(11),
                updated: Default::default(),
                file_system: Some(new_fs()),
            }]])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .into_connection()
    }

    #[actix_rt::test]
    async fn test_is_login_valid_attacker_unknown() {
        let username = String::from("username");
        let password = String::from("password");
        let ip = String::from("ip");
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([
                vec![] as Vec<attacker::Model>,
                vec![attacker::Model {
                    id: 1,
                    ip: ip.clone(),
                    login_count: 8,
                    credentials_id: Some(11),
                    updated: Default::default(),
                    file_system: None,
                }],
            ])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .append_query_results([
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 8,
                }],
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 9,
                }],
            ])
            .append_exec_results([MockExecResult {
                last_insert_id: 11,
                rows_affected: 1,
            }])
            .append_query_results([[attacker_to_credentials::Model {
                attacker_id: 1,
                credentials_id: 11,
            }]])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .into_connection();

        let res = is_login_valid(&username, &password, &ip, &DatabaseImplementation { db }).await;
        assert!(res.is_none());
    }

    #[actix_rt::test]
    async fn test_get_credentials_and_update_count_known() {
        let username = String::from("username");
        let password = String::from("password");
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 5,
                }],
                [credentials::Model {
                    id: 11,
                    username: username.clone(),
                    password: password.clone(),
                    count: 6,
                }],
            ])
            .append_exec_results([MockExecResult {
                last_insert_id: 11,
                rows_affected: 1,
            }])
            .into_connection();

        let res =
            get_credentials_and_update_count(&username, &password, &DatabaseImplementation { db })
                .await;
        assert_eq!(11, res.id.unwrap());
        assert_eq!(6, res.count.unwrap());
        assert_eq!(username, res.username.unwrap());
        assert_eq!(password, res.password.unwrap());
    }

    #[actix_rt::test]
    async fn test_get_credentials_and_update_count_unknown() {
        let username = String::from("username");
        let password = String::from("password");
        let db = MockDatabase::new(DatabaseBackend::MySql)
            .append_query_results([vec![] as Vec<credentials::Model>])
            .append_query_results([[credentials::Model {
                id: 1,
                username: username.clone(),
                password: password.clone(),
                count: 1,
            }]])
            .append_exec_results([MockExecResult {
                last_insert_id: 1,
                rows_affected: 1,
            }])
            .into_connection();

        let res =
            get_credentials_and_update_count(&username, &password, &DatabaseImplementation { db })
                .await;
        assert_eq!(1, res.id.unwrap());
        assert_eq!(1, res.count.unwrap());
        assert_eq!(username, res.username.unwrap());
        assert_eq!(password, res.password.unwrap());
    }
}
