//! Provides the ability to manage old [Attacker][crate::database::models::attacker::Model] database
//! entries and deletes the corresponding files. Furthermore manages the requests sent
//! to the [`VirusTotal API`]
//!
//! [`VirusTotal API`]: https://developers.virustotal.com/reference/overview

use std::time::Duration;

use log::{debug, info};
use tokio::{task, time};

use crate::configuration::config::get_config;
use crate::database::service::DatabaseImplementation;
use crate::database::service_trait::DatabaseTrait;
use crate::external_api::file_service::get_virus_total_result_of_files;
use crate::filesystem::ftp_file_handler::delete_file;

/// Starts a new thread that executes functions continuously at a given interval. Interval is set via Config value [interval][crate::configuration::config::Config#structfield.interval] file.
///
/// # Functions that will be executed:
///
/// [virus_total_manager]
///
/// [clean_up_attackers_and_files]
///
pub fn start_queue(db: DatabaseImplementation) {
    let interval = get_config().interval;
    info!("Starting queue with interval set to {} minutes.", interval);

    task::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(interval * 60));
        loop {
            debug!("Executing recurring functions from queue.");
            interval.tick().await;
            virus_total_manager(&db).await;
            clean_up_attackers_and_files(&db).await;
        }
    });
}

/// Gets all [Uploaded Files][crate::database::models::uploaded_files::Model] Database entries
/// with [Virustotal Result][crate::database::models::uploaded_files::Model#structfield.virustotal_result]
/// equals [None] and uses [get_virus_total_result_of_files] to set a [Value][Some].
///
async fn virus_total_manager(db: &DatabaseImplementation) {
    let virus_total_result = db.get_files_by_missing_virus_total().await;
    debug!(
        "Starting Virus Total management. Found {} UploadedFiles entries with missing Virus Total Result.",
        virus_total_result.len()
    );
    get_virus_total_result_of_files(virus_total_result, db).await;
}

/// Deletes  [Attacker][crate::database::models::attacker::Model]  database entries that were not
/// [updated][crate::database::models::attacker::Model#structfield.updated] in the last 7 days.
/// Additionally, if [file_upload_real][crate::configuration::config::Config#structfield.file_upload_real]
/// is set to true, all files that were physically saved and correspond to these
/// [Attackers][crate::database::models::attacker::Model] will be deleted as well.
///
/// # Functions that will be executed:
///
/// [DatabaseTrait::delete_attacker_if_not_updated_in_one_week]
///
/// [DatabaseTrait::get_files_of_attacker_not_updated_in_one_week]
///
/// [delete_file]
///
async fn clean_up_attackers_and_files(db: &DatabaseImplementation) {
    debug!(
        "Cleaning attackers. Cleaning files is set to {}.  ",
        get_config().file_upload_real
    );
    if get_config().file_upload_real {
        let attackers_to_files = db.get_files_of_attacker_not_updated_in_one_week().await;
        for (attacker, files) in attackers_to_files.iter() {
            debug!(
                "Attacker with ID: '{}' has {} files flagged to delete on drive.",
                attacker.id,
                files.len()
            );
            for file in files.iter() {
                if file.location.is_some() {
                    delete_file("", file.location.as_ref().unwrap().as_str())
                }
            }
        }
    }
    db.delete_attacker_if_not_updated_in_one_week().await;
}
