//! Manages the creation and deletion of real files.

use std::cmp;
use std::fs;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use log::{error, info};
use rand::Rng;

use crate::configuration::config::get_config;

/// Creates a file with random data for a given size, path and filename
///
///
/// * `file_size_in_bytes` - The size of the file in bytes
/// * `path_to_file` - The path to the file, e.g. 'tmp/dir/'
/// * `file_name` - The name of the file, e.g. 'test.txt'
///
///
/// # Example
/// Creates a 15 Byte sized file with random data in main path named test.txt
/// ```
/// create_file(15, "", "test.txt");
/// ```
pub fn create_file(file_size_in_bytes: usize, file_name: String) -> String {
    let mut path = get_config().base_save_path;
    path.push_str(file_name.as_str());

    let f = File::create(path.clone()).unwrap();
    error!(
        "Creating random file with size: {}. File location: {}",
        file_size_in_bytes, path
    );

    let mut writer = BufWriter::new(f);

    let mut rng = rand::thread_rng();
    let mut buffer = [0; 1024];
    let mut remaining_size = file_size_in_bytes;

    while remaining_size > 0 {
        let to_write = cmp::min(remaining_size, buffer.len());
        let buffer = &mut buffer[..to_write];
        rng.fill(buffer);
        writer.write_all(buffer).unwrap();
        remaining_size -= to_write;
    }

    path
}

/// Deletes a file
/// * `path_to_file` - The path to the file, e.g. 'tmp/dir/'
/// * `file_name` - The name of the file, e.g. 'test.txt'
///
/// # Errors
/// Panics if
/// - path points to a directory
/// - file doesn't exist
/// - user lacks permissions to remove the file
///
pub fn delete_file(path_to_file: &str, file_name: &str) {
    info!("Deleting file {}{}", path_to_file, file_name);
    fs::remove_file(format!("{}{}", path_to_file, file_name))
        .unwrap_or_else(|_| panic!("Failed to delete file {}{}", path_to_file, file_name));
}

/// Generates default files for an attacker
///
/// Randomly chooses the given amount of files and copies them to the directory of the user.
/// Uses [the base path][configuration::config::Config#structfield.base_save_path] in addition to
/// the given `path_to_user_dir` as the save directory.
/// Returns an array with the paths to the files.
/// * `path_to_user_dir` - The path the files will be saved in
/// * `amount_of_files_to_copy` - The amount of files that will be copied
///
pub fn generate_files(
    path_to_user_dir: String,
    amount_of_files_to_copy: i32,
) -> Vec<(String, String, u64)> {
    let base_path = get_config().base_save_path;
    let mut result_arr = vec![];
    fs::create_dir_all(format!("{}/{}", base_path, path_to_user_dir))
        .expect("Could not create user directory!");

    let mut rng = rand::thread_rng();
    let mut paths = fs::read_dir("../default_files")
        .unwrap()
        .collect::<Vec<_>>();

    for _ in 0..amount_of_files_to_copy {
        let file_pos = rng.gen_range(0..paths.len());
        let file_src = paths.remove(file_pos).unwrap();

        let dst_path = format!(
            "{}/{}/{}",
            base_path,
            path_to_user_dir,
            file_src.file_name().to_str().unwrap()
        );
        let file_dst = Path::new(&dst_path);

        fs::copy(file_src.path(), file_dst).unwrap();
        let file_name = file_dst.file_name().unwrap().to_str().unwrap().to_string();
        let file_size = file_dst.metadata().unwrap().len();
        result_arr.push((file_dst.display().to_string(), file_name, file_size));
    }
    result_arr
}
