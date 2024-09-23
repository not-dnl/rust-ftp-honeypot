//! This application is an FTP-Honeypot with additional functionalities like:
//! - automatically verifying uploaded files on virustotal
//! - sending results to a given url
//! - highly configurable login logic for attackers (see [login])
//! - custom fake filesystem (see [filesystem])
//! - highly configurable file management (see [configuration])
//! - a queue that manages API calls (see [queue])
//! - implementation (of most) of the necessary FTP verbs (see [honeypot])
//! - logging
//!
//! # Startup
//! To start the application the following steps have to be done.
//! 1. Startup a mysql database. E.g. with the preconfigured docker config we provide: ```docker-compose up```
//! 2. Configure the config file that can be found in ```<path-to-project>/backend/application.toml```
//! 3. (optional) Configure the settings for the logging framework via ```<path-to-project>/backend/log4rs.yml```
//!
//! # Testing
//! Some of the tests are disabled in production mode. To fully test the application enable
//! the ```testing``` feature! This will activate Database mocks to test the [login::login_service]
//! and deactivate problematic other settings

use std::sync::{Arc, Mutex};

use log::{error, info};
use tokio::net::TcpListener;

use database::*;

use crate::configuration::config::get_config;
use crate::database::service::DatabaseImplementation;
use crate::database::service_trait::DatabaseTrait;
use crate::honeypot::handler;
use crate::queue::queue_service::start_queue;

mod configuration;
mod database;
mod external_api;
mod filesystem;
mod honeypot;
mod login;
mod queue;

/// Initializes the logging framework and [starts][start] the app
#[tokio::main]
async fn main() {
    log4rs::init_file("log4rs.yml", Default::default()).expect("Error deserializing log4rs!");

    #[cfg(not(feature = "testing"))]
    start().await;
}

/// Starts the main application logic
#[cfg(not(feature = "testing"))]
async fn start() {
    let db: DatabaseImplementation = match connection::set_up_db("").await {
        Ok(db_2) => {
            info!("Setting up Database Connection finished successfully.");
            DatabaseImplementation { db: db_2 }
        }
        Err(err) => {
            error!("Database Connection setup failed!, Error: {}", err);
            panic!("{}", err)
        }
    };
    create_table(&db).await;

    let ftp_port = get_config().ftp_port;
    let listener = TcpListener::bind(format!("127.0.0.1:{}", ftp_port))
        .await
        .unwrap();
    let current_users = Arc::new(Mutex::new(0));

    start_queue(db.clone());
    loop {
        let (mut tcp_stream, socket) = listener.accept().await.unwrap();
        let socket_string = socket.to_string();
        let vector_string: Vec<&str> = socket_string.split(':').collect();
        let ip = vector_string[0].to_string();
        let db_impl_clone = db.clone();

        tokio::spawn({
            let current_users = Arc::clone(&current_users);
            async move {
                handler::handle_connection(&mut tcp_stream, ip, &db_impl_clone, current_users)
                    .await;
            }
        });
    }
}

/// Create database tables if not existent
async fn create_table(db: &DatabaseImplementation) {
    let credentials_res = db.create_credentials_table().await;
    if credentials_res.is_err() {
        error!(
            "Could not create Credentials table! Error: {}",
            credentials_res.err().unwrap()
        )
    }

    let attacker_res = db.create_attacker_table().await;
    if attacker_res.is_err() {
        error!(
            "Could not create Attacker table! Error: {}",
            attacker_res.err().unwrap()
        )
    } else {
        db.update_attacker_table()
            .await
            .expect("Could not set default and on update for Attacker table");
    }

    let uploaded_files_res = db.create_uploaded_files_table().await;
    if uploaded_files_res.is_err() {
        error!(
            "Could not create Uploaded Files table! Error: {}",
            uploaded_files_res.err().unwrap()
        )
    }

    let attacker_to_credentials_res = db.create_attacker_to_credentials_table().await;
    if attacker_to_credentials_res.is_err() {
        error!(
            "Could not create AttackerToCredentials table! Error: {}",
            attacker_to_credentials_res.err().unwrap()
        )
    }
}
