use std::path::PathBuf;

use tempfile::TempDir;

#[allow(dead_code)]
pub 
fn make_temp_dir_no_file() -> TempDir
{
    let dir = tempfile::tempdir().unwrap();

    return dir;
}

#[allow(dead_code)]
pub 
fn make_temp_dir(path: &str) -> (PathBuf, TempDir)
{
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(path);

    return (path, dir);
}

