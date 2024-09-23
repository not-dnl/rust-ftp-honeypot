//! Represents a directory of the fake filesystem.

use std::collections::HashMap;

use chrono::Local;
use serde::{Deserialize, Serialize};

use crate::filesystem::models::ftp_file::FtpFile;

#[derive(Serialize, Deserialize, sea_orm::FromJsonQueryResult, Clone, Debug, PartialEq, Eq)]
pub struct FtpNode {
    pub decoration: String,
    pub size: i64,
    pub files: Vec<FtpFile>,
    pub dirs: HashMap<String, Box<FtpNode>>,
    pub timestamp: String,
}

/// Generates a new [Directory][crate:: FtpNode] with the current timestamp.
///
/// # Functions that will be executed:
///
/// [virus_total_manager]
///
/// [clean_up_attackers_and_files]
///
pub fn generate_dir(dir_name: &str, size: i64) -> FtpNode {
    let date = Local::now();
    FtpNode {
        decoration: dir_name.to_string(),
        size,
        files: vec![],
        dirs: Default::default(),
        timestamp: date.format("%b %d %H:%M").to_string(),
    }
}

impl FtpNode {
    pub fn cd(&mut self, path: &[String]) -> bool {
        if path.is_empty() {
            return true;
        }
        if self.dirs.contains_key(&path[0]) {
            self.dirs.get_mut(&path[0]).unwrap().cd(&path[1..])
        } else {
            false
        }
    }

    fn ls(&mut self) -> String {
        let mut result = String::new();

        let mut child_node_values: Vec<_> = self.dirs.values().collect();
        child_node_values.sort_by(|a, b| a.decoration.cmp(&b.decoration));

        for child_node in child_node_values {
            result = format!("{}\r\n{}", result, child_node.decoration);
        }

        self.files.sort_by(|a, b| a.name.cmp(&b.name));

        for file in self.files.iter() {
            result = format!("{}\r\n{}", result, file.name);
        }

        if !result.is_empty() {
            result.remove(0);
            result.remove(0);
        }
        result
    }

    fn ls_extended_information(&mut self, attacker_id: i64) -> String {
        let mut result = String::new();

        let mut child_node_values: Vec<_> = self.dirs.values().collect();
        child_node_values.sort_by(|a, b| a.decoration.cmp(&b.decoration));
        let ftp_user_id = attacker_id + 1000;

        for child_node in child_node_values {
            result = format!(
                "{}\r\ndrwxr-sr-x\t1 {}\t{}\t\t{} {} {}",
                result,
                ftp_user_id,
                ftp_user_id,
                child_node.size,
                child_node.timestamp,
                child_node.decoration
            );
        }

        self.files.sort_by(|a, b| a.name.cmp(&b.name));

        for file in self.files.iter() {
            result = format!(
                "{}\r\n-rw-r--r--\t1 {}\t{}\t\t{} {} {}",
                result, ftp_user_id, ftp_user_id, file.size, file.timestamp, file.name
            );
        }

        if !result.is_empty() {
            result.remove(0);
            result.remove(0);
        }

        result
    }

    pub fn ls_path(&mut self, path: &[String]) -> String {
        let (node, _) = self.traverse_path(path);
        node.ls()
    }
    pub fn ls_path_extended_information(&mut self, path: &[String], attacker_id: i64) -> String {
        let (node, _) = self.traverse_path(path);
        node.ls_extended_information(attacker_id)
    }

    pub fn ls_path_extended_minus_a_information(
        &mut self,
        path: &[String],
        attacker_id: i64,
    ) -> String {
        let (node, _) = self.traverse_path(path);

        let mut result = String::new();
        let ftp_user_id = attacker_id + 1000;
        result = format!(
            "{}\r\ndrwxr-sr-x\t1 {}\t{}\t\t{} Mar 16 21:23 .",
            result, ftp_user_id, ftp_user_id, 0
        );
        result = format!(
            "{}\r\ndrwxr-sr-x\t1 {}\t{}\t\t{} Mar 13 19:59 ..\r\n",
            result, ftp_user_id, ftp_user_id, 0
        );
        result = format!("{}{}", result, node.ls_extended_information(attacker_id));
        result
    }

    pub fn traverse_path<'p>(&mut self, path: &'p [String]) -> (&mut FtpNode, &'p [String]) {
        if !path.is_empty() && !self.dirs.is_empty() && self.dirs.contains_key(&path[0]) {
            self.dirs
                .get_mut(&path[0])
                .unwrap()
                .traverse_path(&path[1..])
        } else {
            (self, path)
        }
    }
}
