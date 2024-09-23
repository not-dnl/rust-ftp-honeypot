//! Services that work on the hashcreation, creating of files in the database, creating virus total results and pushing the data to the frontend

use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use log::{error, info, warn};
use reqwest::header::{HeaderValue, USER_AGENT};
use reqwest::*;
use sea_orm::ActiveValue::Set;
use sea_orm::IntoActiveModel;
use serde_json::json;

use crate::configuration::config::get_config;
use crate::database::models::uploaded_files::Model;
use crate::database::service::DatabaseImplementation;
use crate::database::service_trait::DatabaseTrait;

/// takes all the files that have no virustotal result and makes a request to virustotal for them
///
/// and then sends the new full model to  the frontend to see
///
/// # the function gets  and Vec of all the files without virustotal-result [file::Model#virustotal_result]
///
/// ## it goes into a loop for all Files in the Vector of [Model]
///
/// ### for every file we create an virustotal result were we sent the hash and our api-key to virus-total
///
/// #### then we take the response and put it in the Model
///
/// and then we create a json from that model and send it with post-json to the frontend
///
/// the loop contiunes until
///
/// 1 the vector is empty
///
/// 2 or the virustotal api gives us an 429 code so we make to many requests and we break out of the loop and go out of the function

pub async fn get_virus_total_result_of_files(files: Vec<Model>, db: &DatabaseImplementation) {
    let api_key = get_config().virus_total_token;
    for model in files {
        let model_id = model.id.clone();
        info!("Start processing of file with file_id: {}", model_id);
        let attacker_id = model.attacker_id.unwrap_or_default();

        let model_hash = model.clone().hash.unwrap();
        let url = format!("{}{}", get_config().virus_total_hash_url, model_hash);

        let client = Client::builder()
            .user_agent(USER_AGENT)
            .build()
            .expect("Could not build client!");
        let response = client
            .get(&url)
            .header("x-apikey", HeaderValue::from_str(&api_key).unwrap())
            .send()
            .await
            .expect("Could not get response!");

        let response_code = response.status();

        let vt_result_negative = String::from("Hash not found on VT.");
        let mut updated_model = model.into_active_model();

        if response_code == StatusCode::OK {
            let vt_link = format!(
                "{}/{}/details",
                get_config().virus_total_result_url,
                &model_hash
            );
            info!("Found file with file_id: {} on VT ({})", model_id, vt_link);
            updated_model.virustotal_result = Set(Option::from(vt_link));
        } else if response_code == 429 {
            info!("VT daily limit reached! Stopped sending requests.");
            break;
        } else {
            warn!("Did not find file with file_id: {} on VT.", model_id);
            updated_model.virustotal_result = Set(Option::from(vt_result_negative.to_string()));
        }

        let mut json_string_only = String::new();

        let attacker_ip: String = match db.get_attacker_by_id(attacker_id).await {
            None => "IP not found!".to_string(),
            Some(attacker) => attacker.ip,
        };
        let file_json = create_json_string_fileupload(
            "file".to_string(),
            attacker_ip,
            updated_model.filename.clone().unwrap().to_string(),
            model_hash.to_string(),
            updated_model.size.clone().unwrap().to_string(),
            updated_model
                .virustotal_result
                .clone()
                .unwrap()
                .unwrap()
                .to_string(),
        );

        match file_json {
            Ok(json_string) => {
                json_string_only = json_string;
            }
            Err(error) => {
                println!("Error: {}", error);
            }
        };

        match post_json(json_string_only).await {
            Ok(json_string) => {
                info!(
                    "Uploaded file with file_id: {} to Frontend. JSON string of request: {}",
                    model_id, json_string
                );
            }
            Err(error) => {
                error!(
                    "Error while uploading file with file_id: {} to Frontend. Error: {}",
                    model_id, error
                );
            }
        };
        db.update_file(updated_model).await;
    }
}

/// creates the fileupload json for the frontend from the Data provided
pub fn create_json_string_fileupload(
    event_type: String,
    src_ip: String,
    fname: String,
    sha256: String,
    size: String,
    vt_result: String,
) -> Result<String> {
    let timestamp: DateTime<Utc> = Utc::now();
    let timestamp_str = timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
    let honeynet_id = get_config().honeynet_id;
    let token = get_config().honeynet_token;

    let hash_res = format!("{} | {}", sha256, vt_result);
    let event = json!({
        "honeypotID": honeynet_id,
        "token": token,
        "timestamp": timestamp_str,
        "type": event_type,
        "content": {
            "srcIP": src_ip,
            "service": "ftp",
            "fname": fname,
            "sha1": hash_res,
            "size": size
        }
    });
    let json_str = json!({ "event": event });
    Ok(json_str.to_string())
}

/// creates the Login json for the frontend from the Data prvided and sends it
pub async fn create_json_and_send_request(ip: &str, username: &str, password: &str) {
    let timestamp: DateTime<Utc> = Utc::now();
    let timestamp_str = timestamp.format("%Y-%m-%d %H:%M:%S").to_string();

    let honeynet_id = get_config().honeynet_id;
    let honeynet_token = get_config().honeynet_token;
    let event = json!({
        "honeypotID": honeynet_id,
        "token": honeynet_token,
        "timestamp": timestamp_str,
        "type": "login",
        "content": {
            "srcIP": ip,
            "service": "ftp",
            "user": username,
            "pass": password
        }
    });

    let json_str = json!({ "event": event });

    let response = post_json(json_str.to_string()).await;
    match response {
        Ok(body) => info!("Successfully sent request to Honeynet with body: {}", body),
        Err(e) => error!("Error response from Honeynet: {}", e),
    }
}

/// Sends the json provided with a post request to [configuration::config::Config#structfield.honeynet_url]
pub async fn post_json(json_string: String) -> reqwest::Result<String> {
    info!("Start request with: {}", json_string);

    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true) // TODO, FIXME: Important, do you really want to have a man in the middle?
        .timeout(Duration::from_secs(10))
        .build()?;
    let response = client
        .post(get_config().honeynet_url)
        .header("Content-Type", "application/json")
        .body(json_string.to_owned())
        .send()
        .await?;
    response.text().await
}

#[cfg(test)]
mod test {
    use super::*;

    #[actix_rt::test]
    async fn test_create_json_string() {
        // Test case with valid input
        let result = create_json_string_fileupload(
            "file".to_string(),
            "127.0.0.1".to_string(),
            "upload.exe".to_string(),
            "hash_value".to_string(),
            "file_size".to_string(),
            "result".to_string(),
        );
        assert!(result.is_ok());

        // Test case with invalid input (empty token)
        let result = create_json_string_fileupload(
            "file".to_string(),
            "127.0.0.1".to_string(),
            "upload.exe".to_string(),
            "hash_value".to_string(),
            "file_size".to_string(),
            "result".to_string(),
        );
        assert!(result.is_ok());
    }
}
