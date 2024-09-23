//! Represents the filesystem.

use std::collections::HashMap;

use chrono::{Duration, Local};
use rand::Rng;
use sea_orm::ActiveValue::Set;
use sea_orm::Update;
use serde::{Deserialize, Serialize};

use crate::configuration::config::get_config;
use crate::database::models::{attacker, uploaded_files};
use crate::database::service::DatabaseImplementation;
use crate::database::service_trait::DatabaseTrait;
use crate::filesystem::ftp_file_handler::{create_file, generate_files};
use crate::filesystem::models::ftp_file::FtpFile;
use crate::filesystem::models::ftp_node::{generate_dir, FtpNode};

#[derive(Serialize, Deserialize, sea_orm::FromJsonQueryResult, Clone, Debug, PartialEq, Eq)]
/// Represents the full filesystem
pub struct FtpFileSystem {
    pub root: Box<FtpNode>,
    pub path: Vec<String>,
}

/// Creates a default filesystem with some directories and files
#[allow(dead_code)]
pub fn new_fs() -> FtpFileSystem {
    let sub_node_1 = Box::new(FtpNode {
        decoration: String::from("pictures"),
        dirs: HashMap::new(),
        files: vec![],
        size: 0,
        timestamp: String::from("Mar 13 19:59"),
    });

    let sub_sub_node_1 = Box::new(FtpNode {
        decoration: String::from("invoices"),
        dirs: HashMap::new(),
        files: vec![],
        size: 0,
        timestamp: String::from("Mar 18 15:35"),
    });
    let sub_sub_node_2 = Box::new(FtpNode {
        decoration: String::from("private"),
        dirs: HashMap::new(),
        files: vec![],
        size: 0,
        timestamp: String::from("Mar 25 17:03"),
    });
    let mut node_1_map = HashMap::new();
    node_1_map.insert(String::from("invoices"), sub_sub_node_1);
    node_1_map.insert(String::from("private"), sub_sub_node_2);

    let sub_node_2 = Box::new(FtpNode {
        decoration: String::from("documents"),
        dirs: node_1_map,
        files: vec![],
        size: 0,
        timestamp: String::from("Mar 17 22:31"),
    });
    let mut root_map = HashMap::new();
    root_map.insert(String::from("pictures"), sub_node_1);
    root_map.insert(String::from("documents"), sub_node_2);

    let root_node: Box<FtpNode> = Box::new(FtpNode {
        decoration: String::from("root"),
        dirs: root_map,
        files: vec![],
        size: 0,
        timestamp: String::from("Mar 17 18:08"),
    });
    FtpFileSystem {
        root: root_node,
        path: Vec::new(),
    }
}

/// Returns a timestamp with randomized input.
///
/// Randomized timestamp will always be between the current time and one year in the past
pub fn get_randomized_timestamp() -> String {
    let mut date = Local::now();
    let mut rng = rand::thread_rng();

    date -= Duration::days(rng.gen_range(0..150));
    date -= Duration::hours(-rng.gen_range(0..150));
    date -= Duration::minutes(-rng.gen_range(0..150));
    date -= Duration::seconds(-rng.gen_range(0..150));
    date -= Duration::weeks(-rng.gen_range(0..15));

    return date.format("%b %d %H:%M").to_string();
}

/// Parser to generate valid [FtpFile] objects from the given file parameters
///
/// Uses randomization for the timestamp
///
/// * `files: Vec<(String, String, u64)>` - File information in format
/// ( file path, file name, file size )
pub fn parse_to_file_vec(files: Vec<(String, String, u64)>) -> Vec<FtpFile> {
    let mut ftp_files = vec![];
    for (file_path, file_name, file_size) in files {
        let file = FtpFile {
            name: file_name,
            size: i64::try_from(file_size).unwrap(),
            file_id: None,
            timestamp: get_randomized_timestamp(),
            default_file: Some(file_path),
        };
        ftp_files.push(file)
    }
    ftp_files
}

/// Creates a default filesystem with some directories and default files
pub fn new_fs_of_attacker(attacker_id: i64) -> FtpFileSystem {
    let attacker_name = format!("{}", attacker_id);
    let files = generate_files(attacker_name, 15);
    let ftp_files = parse_to_file_vec(files);

    let sub_node_1 = Box::new(FtpNode {
        decoration: String::from("pictures"),
        dirs: HashMap::new(),
        files: ftp_files[0..1].to_owned(),
        size: 0,
        timestamp: get_randomized_timestamp(),
    });

    let sub_sub_node_1 = Box::new(FtpNode {
        decoration: String::from("invoices"),
        dirs: HashMap::new(),
        files: ftp_files[2..4].to_owned(),
        size: 0,
        timestamp: get_randomized_timestamp(),
    });
    let sub_sub_node_2 = Box::new(FtpNode {
        decoration: String::from("private"),
        dirs: HashMap::new(),
        files: ftp_files[5..9].to_owned(),
        size: 0,
        timestamp: get_randomized_timestamp(),
    });
    let mut node_1_map = HashMap::new();
    node_1_map.insert(String::from("invoices"), sub_sub_node_1);
    node_1_map.insert(String::from("private"), sub_sub_node_2);

    let sub_node_2 = Box::new(FtpNode {
        decoration: String::from("documents"),
        dirs: node_1_map,
        files: ftp_files[10..13].to_owned(),
        size: 0,
        timestamp: get_randomized_timestamp(),
    });
    let mut root_map = HashMap::new();
    root_map.insert(String::from("pictures"), sub_node_1);
    root_map.insert(String::from("documents"), sub_node_2);

    let root_node: Box<FtpNode> = Box::new(FtpNode {
        decoration: String::from("root"),
        dirs: root_map,
        files: ftp_files[13..14].to_owned(),
        size: 0,
        timestamp: get_randomized_timestamp(),
    });
    FtpFileSystem {
        root: root_node,
        path: Vec::new(),
    }
}

impl FtpFileSystem {
    pub async fn clear_path(&mut self, db: &DatabaseImplementation, attacker_id: i64) {
        self.path = vec![];
        self.update_fs(db, attacker_id).await;
    }
    pub async fn get_physical_file_path(
        &mut self,
        db: &DatabaseImplementation,
        file_name_and_path: &str,
    ) -> (bool, Option<String>) {
        let mut path_as_vec = file_name_and_path
            .split_terminator('/')
            .map(str::to_string)
            .collect::<Vec<String>>();
        let file_name = path_as_vec.pop().unwrap();
        let is_path_valid = self.resolve_path_as_vec(path_as_vec.clone());
        let can_be_downloaded = get_config().can_be_downloaded;
        match is_path_valid {
            Some(path) => {
                let (node, _) = self.root.traverse_path(path.as_slice());
                let file = node.files.iter().find(|file| file.name.eq(&file_name));
                match file {
                    None => (can_be_downloaded, None),
                    Some(file) => {
                        if file.default_file.is_some() {
                            return (can_be_downloaded, file.default_file.to_owned());
                        }

                        if !get_config().can_be_downloaded {
                            return (
                                can_be_downloaded,
                                Some(create_file(file.size as usize, file.name.clone())),
                            );
                        }
                        let db_file = db
                            .get_file_by_id(file.file_id.unwrap())
                            .await
                            .expect("Could not find file on database!");
                        (can_be_downloaded, db_file.location)
                    }
                }
            }
            _ => (can_be_downloaded, None),
        }
    }
    pub async fn update_fs(&mut self, db: &DatabaseImplementation, attacker_id: i64) {
        Update::one(attacker::ActiveModel {
            id: Set(attacker_id),
            file_system: Set(Some(self.clone())),
            ..Default::default()
        })
        .exec(&db.db)
        .await
        .expect("Could not update filesystem!");
    }

    pub async fn save_dir(
        &mut self,
        db: &DatabaseImplementation,
        attacker_id: i64,
        file_name_and_path: &str,
    ) -> bool {
        let mut split_string = file_name_and_path
            .split_terminator('/')
            .map(str::to_string)
            .collect::<Vec<String>>();
        let dir_to_add = split_string.pop().unwrap();

        let is_path_valid = self.resolve_path_as_vec(split_string);
        match is_path_valid {
            None => false,
            Some(path) => {
                let (node, _) = self.root.traverse_path(path.as_slice());
                if node.dirs.contains_key(&dir_to_add) {
                    false
                } else {
                    node.dirs.insert(
                        String::from(dir_to_add.clone()),
                        Box::new(generate_dir(&dir_to_add, 0)),
                    );
                    self.update_fs(db, attacker_id).await;
                    true
                }
            }
        }
    }
    pub async fn rm_dir(
        &mut self,
        db: &DatabaseImplementation,
        attacker_id: i64,
        file_name_and_path: &str,
    ) -> bool {
        let mut split_string = file_name_and_path
            .split_terminator('/')
            .map(str::to_string)
            .collect::<Vec<String>>();
        let dir_to_remove = split_string.pop().unwrap();

        let is_path_valid = self.resolve_path_as_vec(split_string);
        match is_path_valid {
            None => false,
            Some(path) => {
                let (node, _) = self.root.traverse_path(path.as_slice());
                let directory = node.dirs.get(&dir_to_remove);
                if directory.is_some()
                    && directory.unwrap().files.is_empty()
                    && directory.unwrap().dirs.is_empty()
                {
                    node.dirs.remove(&dir_to_remove);
                    self.update_fs(db, attacker_id).await;
                    true
                } else {
                    false
                }
            }
        }
    }
    pub async fn rm_file(
        &mut self,
        db: &DatabaseImplementation,
        attacker_id: i64,
        file_name_and_path: &str,
    ) -> bool {
        let mut split_string = file_name_and_path
            .split_terminator('/')
            .map(str::to_string)
            .collect::<Vec<String>>();
        let file_name = split_string.pop().unwrap();

        let is_path_valid = self.resolve_path_as_vec(split_string);
        match is_path_valid {
            None => false,
            Some(path) => {
                let (node, _) = self.root.traverse_path(path.as_slice());

                let index = node.files.iter().position(|f| f.name.eq(&file_name));
                if index.is_some() {
                    node.files.remove(index.unwrap());
                    self.update_fs(db, attacker_id).await;
                    true
                } else {
                    false
                }
            }
        }
    }
    pub async fn save_file(
        &mut self,
        db: &DatabaseImplementation,
        attacker_id: i64,
        path_to_physical_file: &str,
        file_name_and_path: &str,
        file_size: i64,
        file_hash: String,
    ) {
        let mut split_string = file_name_and_path
            .split_terminator('/')
            .map(str::to_string)
            .collect::<Vec<String>>();
        let file_name = split_string.pop().unwrap();
        let is_path_valid = self.resolve_path_as_vec(split_string);
        if let Some(path) = is_path_valid {
            let mut file = uploaded_files::ActiveModel {
                filename: Set(file_name.clone()),
                attacker_id: Set(Some(attacker_id)),
                size: Set(file_size),
                hash: Set(Some(file_hash)),
                ..Default::default()
            };

            if get_config().file_upload_real {
                file.location = Set(Some(path_to_physical_file.to_string()))
            }

            let db_file = db.update_file(file).await;
            let (node, _) = self.root.traverse_path(path.as_slice());
            let date = Local::now();
            node.size += file_size;
            node.files.push(FtpFile {
                name: file_name,
                size: file_size,
                file_id: Some(db_file.id.unwrap()),
                timestamp: date.format("%b %d %H:%M").to_string(),
                default_file: None,
            });
            self.update_fs(db, attacker_id).await
        }
    }
    pub fn traverse_path<'p>(&mut self, path: &'p [String]) -> (&mut FtpNode, &'p [String]) {
        self.root.traverse_path(path)
    }

    pub fn cd_as_str(&mut self, path_to_move: &str) -> bool {
        let split_string = path_to_move
            .split_terminator('/')
            .map(str::to_string)
            .collect::<Vec<String>>();
        self.real_cd(split_string)
    }

    pub fn real_cd(&mut self, mut path_to_move: Vec<String>) -> bool {
        let mut tmp_path = self.path.clone();
        if !path_to_move.is_empty() && path_to_move.get(0).unwrap().eq("") {
            tmp_path = vec![];
            path_to_move.remove(0);
        }

        if !path_to_move.is_empty() && path_to_move.get(0).unwrap().eq(".") {
            path_to_move.remove(0);
        }

        return match self.real_cd_rec(path_to_move.as_slice(), &mut tmp_path) {
            None => false,
            Some(new_path) => {
                self.path = new_path.clone();
                true
            }
        };
    }

    fn real_cd_rec<'p>(
        &mut self,
        path_to_move: &[String],
        tmp_path: &'p mut Vec<String>,
    ) -> Option<&'p Vec<String>> {
        if path_to_move.is_empty() {
            return Some(tmp_path);
        }
        if path_to_move[0].eq("..") {
            tmp_path.pop();
            self.real_cd_rec(&path_to_move[1..], tmp_path)
        } else {
            let mut cloned_path = tmp_path.clone();
            cloned_path.push(path_to_move[0].clone());
            let new_path = cloned_path.as_slice();
            if self.root.cd(new_path) {
                tmp_path.push(path_to_move[0].clone());
                return self.real_cd_rec(&path_to_move[1..], tmp_path);
            } else {
                None
            }
        }
    }

    pub fn ls(&mut self) -> String {
        self.root.ls_path(&self.path)
    }

    pub fn ls_minus_a_extended_information(&mut self, attacker_id: i64) -> String {
        self.root
            .ls_path_extended_minus_a_information(&self.path, attacker_id)
    }

    pub fn ls_extended_information(&mut self, attacker_id: i64) -> String {
        self.root
            .ls_path_extended_information(&self.path, attacker_id)
    }

    pub fn ls_extended_information_with_str(
        &mut self,
        attacker_id: i64,
        path_to_move: &str,
    ) -> Option<String> {
        let is_path_valid = self.resolve_path(path_to_move);
        match is_path_valid {
            None => None,
            Some(path) => Some(self.root.ls_path_extended_information(&path, attacker_id)),
        }
    }

    pub fn ls_path(&mut self, path_to_move: &str) -> Option<String> {
        let is_path_valid = self.resolve_path(path_to_move);
        match is_path_valid {
            None => None,
            Some(path) => Some(self.root.ls_path(&path)),
        }
    }

    pub fn resolve_path(&mut self, path_to_move: &str) -> Option<Vec<String>> {
        let add_path = path_to_move
            .split_terminator('/')
            .map(str::to_string)
            .collect::<Vec<String>>();
        self.resolve_path_as_vec(add_path)
    }
    fn resolve_path_as_vec(&mut self, mut add_path: Vec<String>) -> Option<Vec<String>> {
        let mut tmp_path = self.path.clone();

        if !add_path.is_empty() && add_path.get(0).unwrap().eq("") {
            tmp_path = vec![];
            add_path.remove(0);
        }

        if !add_path.is_empty() && add_path.get(0).unwrap().eq(".") {
            add_path.remove(0);
        }

        let is_path_valid = self.real_cd_rec(add_path.as_slice(), &mut tmp_path);
        is_path_valid.cloned()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::filesystem::ftp_fs::{FtpFileSystem, FtpNode};
    use crate::filesystem::models::ftp_file::FtpFile;

    fn ini_tree() -> FtpFileSystem {
        let sub_node_1 = Box::new(FtpNode {
            decoration: String::from("node1"),
            dirs: HashMap::new(),
            files: vec![],
            size: 0,
            timestamp: String::from("Mar 13 19:59"),
        });

        let sub_sub_node_1 = Box::new(FtpNode {
            decoration: String::from("sub_node_1"),
            dirs: HashMap::new(),
            files: vec![],
            size: 0,
            timestamp: String::from("Mar 13 19:59"),
        });
        let sub_sub_node_2 = Box::new(FtpNode {
            decoration: String::from("sub_node_2"),
            dirs: HashMap::new(),
            files: vec![],
            size: 0,
            timestamp: String::from("Mar 13 19:59"),
        });
        let mut node_1_map = HashMap::new();
        node_1_map.insert(String::from("sub_node_1"), sub_sub_node_1);
        node_1_map.insert(String::from("sub_node_2"), sub_sub_node_2);

        let sub_node_2 = Box::new(FtpNode {
            decoration: String::from("node2"),
            dirs: node_1_map,
            files: vec![],
            size: 0,
            timestamp: String::from("Mar 13 19:59"),
        });
        let mut root_map = HashMap::new();
        root_map.insert(String::from("node1"), sub_node_1);
        root_map.insert(String::from("node2"), sub_node_2);

        let root_node: Box<FtpNode> = Box::new(FtpNode {
            decoration: String::from("testroot"),
            dirs: root_map,
            files: vec![],
            size: 0,
            timestamp: String::from("Mar 13 19:59"),
        });
        FtpFileSystem {
            root: root_node,
            path: Vec::new(),
        }
    }

    #[test]
    fn cd_to_child() {
        let mut tree = ini_tree();
        let to_move = "node1";
        let res = tree.cd_as_str(to_move);
        assert_eq!(tree.path, vec!["node1"]);
        assert!(res);
    }

    #[test]
    fn cd_to_parent_in_root() {
        let mut tree = ini_tree();
        let to_move = "../";
        let res = tree.cd_as_str(to_move);
        assert!(tree.path.is_empty());
        assert!(res);
    }

    #[test]
    fn cd_to_parent_in_child() {
        let mut tree = ini_tree();

        let to_move = "node1";
        tree.cd_as_str(to_move);

        let to_move = "../";
        let res = tree.cd_as_str(to_move);
        assert!(tree.path.is_empty());
        assert!(res);
    }

    #[test]
    fn cd_to_parent_in_middle_of_string() {
        let mut tree = ini_tree();

        let to_move = "node1/../node2/sub_node_1";
        let res = tree.cd_as_str(to_move);

        assert_eq!(tree.path, vec!["node2", "sub_node_1"]);
        assert!(res);
    }

    #[test]
    fn cd_to_parent_several_times() {
        let mut tree = ini_tree();

        let to_move = "../../../../../../";
        let res = tree.cd_as_str(to_move);

        assert!(tree.path.is_empty());
        assert!(res);
    }

    #[test]
    fn cd_to_invalid_dir() {
        let mut tree = ini_tree();

        let to_move = "invalid_dir";
        let res = tree.cd_as_str(to_move);

        assert!(!res);
    }

    #[test]
    fn cd_keeps_old_path_if_invalid() {
        let mut tree = ini_tree();

        let to_move = "node1/";
        tree.cd_as_str(to_move);

        let to_move = "../node2/sub_node_1/invalid_dir";
        let res = tree.cd_as_str(to_move);

        assert_eq!(tree.path, vec!["node1"]);
        assert!(!res);
    }

    #[test]
    fn ls_in_root() {
        let mut tree = ini_tree();

        let res = tree.ls();
        let cmp = "node1\r\nnode2";
        assert_eq!(cmp, res);
    }

    #[test]
    fn ls_in_sub_node() {
        let mut tree = ini_tree();
        let to_move = "node2";
        tree.cd_as_str(to_move);

        let res = tree.ls();
        let cmp = "sub_node_1\r\nsub_node_2";
        assert_eq!(cmp, res);
    }

    #[test]
    fn ls_with_files() {
        let mut tree = ini_tree();
        let file1 = FtpFile {
            name: "atestfile.txt".to_string(),
            size: 0,
            file_id: None,
            timestamp: String::from("Mar 13 19:59"),
            default_file: None,
        };
        let file2 = FtpFile {
            name: "ztesting.yaml".to_string(),
            size: 0,
            file_id: None,
            timestamp: String::from("Mar 13 19:59"),
            default_file: None,
        };

        tree.root.files.push(file1);
        tree.root.files.push(file2);
        let res = tree.ls();
        let cmp = "node1\r\nnode2\r\natestfile.txt\r\nztesting.yaml";
        assert_eq!(cmp, res);
    }

    #[test]
    fn ls_in_empty_dir() {
        let mut tree = ini_tree();
        let to_move = "node1";
        tree.cd_as_str(to_move);

        let res = tree.ls();
        let cmp = "";
        assert_eq!(cmp, res);
    }

    #[test]
    fn ls_extended_in_root() {
        let mut tree = ini_tree();

        let res = tree.ls_extended_information(1);
        let cmp =
            "drwxr-sr-x	1 1001	1001		0 Mar 13 19:59 node1\r\ndrwxr-sr-x	1 1001	1001		0 Mar 13 19:59 node2";
        assert_eq!(cmp, res);
    }

    #[test]
    fn ls_extended_in_sub_node() {
        let mut tree = ini_tree();
        let to_move = "node2";
        tree.cd_as_str(to_move);

        let res = tree.ls_extended_information(1);
        let cmp =
            "drwxr-sr-x	1 1001	1001		0 Mar 13 19:59 sub_node_1\r\ndrwxr-sr-x	1 1001	1001		0 Mar 13 19:59 sub_node_2";
        assert_eq!(cmp, res);
    }

    #[test]
    fn ls_extended_with_files() {
        let mut tree = ini_tree();
        let file1 = FtpFile {
            name: "atestfile.txt".to_string(),
            size: 0,
            file_id: None,
            timestamp: String::from("Mar 13 19:59"),
            default_file: None,
        };
        let file2 = FtpFile {
            name: "ztesting.yaml".to_string(),
            size: 0,
            file_id: None,
            timestamp: String::from("Mar 13 19:59"),
            default_file: None,
        };

        tree.root.files.push(file1);
        tree.root.files.push(file2);
        let res = tree.ls_extended_information(1);
        let res2 = tree.ls_extended_information_with_str(1, "");

        let cmp =
            "drwxr-sr-x	1 1001	1001		0 Mar 13 19:59 node1\r\ndrwxr-sr-x	1 1001	1001		0 Mar 13 19:59 node2\r\n-rw-r--r--	1 1001	1001		0 Mar 13 19:59 atestfile.txt\r\n-rw-r--r--	1 1001	1001		0 Mar 13 19:59 ztesting.yaml";

        assert_eq!(cmp, res);
        assert_eq!(cmp, res2.unwrap());
    }

    #[test]
    fn ls_extended_in_empty_dir() {
        let mut tree = ini_tree();
        let to_move = "node1";
        tree.cd_as_str(to_move);

        let res = tree.ls_extended_information(1);
        let cmp = "";
        assert_eq!(cmp, res);
    }

    #[test]
    fn ls_extended_to_sub_node() {
        let mut tree = ini_tree();
        let res = tree.ls_extended_information_with_str(1, "node2");
        let cmp =
            "drwxr-sr-x	1 1001	1001		0 Mar 13 19:59 sub_node_1\r\ndrwxr-sr-x	1 1001	1001		0 Mar 13 19:59 sub_node_2";
        assert_eq!(cmp, res.unwrap());
    }
}
