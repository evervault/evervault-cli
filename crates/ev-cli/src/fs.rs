use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, DirEntry, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::{env, path};
use thiserror::Error;
use toml;
use zip;
use zip::write::FileOptions;

#[derive(Debug, Deserialize, Serialize)]
struct TomlFile {
    function: FunctionToml,
}

#[derive(Debug, Deserialize, Serialize)]
struct FunctionToml {
    name: String,
    language: String,
    #[serde(default = "default_handler")]
    handler: String,
}

fn default_handler() -> String {
    "index.handler".to_string()
}

pub fn get_current_dir() -> Result<path::PathBuf, FsError> {
    Ok(env::current_dir()?)
}

#[derive(Debug, Error)]
pub enum FsError {
    #[error("There was an error reading the function toml file")]
    MalfordFunctionToml,
    #[error("An IO error occurred: {0}")]
    Io(std::io::Error),
    #[error("An error occurred while serializing the file")]
    SerializationError,
}

impl From<std::io::Error> for FsError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

pub fn validate_function_toml() -> Result<(), FsError> {
    let path = get_current_dir()?.join("function.toml");

    let file = File::open(&path)?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents)?;

    let _toml: TomlFile = toml::from_str(&contents).map_err(|_| FsError::MalfordFunctionToml)?;
    Ok(())
}

pub fn get_current_function_name() -> Result<String, FsError> {
    let path = get_current_dir()?.join("function.toml");

    let file = File::open(&path)?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents)?;

    let toml: TomlFile = toml::from_str(&contents).unwrap();
    let function_config = toml.function;
    let function_name = function_config.name;
    Ok(function_name)
}

pub fn get_current_function_language() -> Result<String, FsError> {
    let path = get_current_dir()?.join("function.toml");

    let file = File::open(&path)?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents)?;

    let toml: TomlFile = toml::from_str(&contents).unwrap();
    let function_config = toml.function;
    let function_language = function_config.language;
    Ok(function_language)
}

pub fn set_function_name(new_name: &str, path: Option<&str>) -> Result<(), FsError> {
    let path = path
        .map(|p| PathBuf::from(p))
        .unwrap_or(get_current_dir()?)
        .join("function.toml");
    let mut file = File::open(&path)?;

    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let mut package: TomlFile =
        toml::from_str(&contents).map_err(|_| FsError::MalfordFunctionToml)?;

    package.function.name = new_name.to_string();

    let toml = toml::to_string(&package).expect("Unable to convert to toml!");

    std::fs::write(&path, toml);
    Ok(())
}

pub fn extract_zip(tmpfile: File, target_dir: PathBuf) -> Result<String, FsError> {
    let mut zip = zip::ZipArchive::new(tmpfile).unwrap();

    if !target_dir.exists() {
        create_dir_all(target_dir.clone())?;
    }

    zip.extract(&target_dir)
        .map(|_| target_dir.to_str().unwrap().to_string())
        .map_err(|e| FsError::Io(std::io::Error::from(e)))
}

pub fn copy_folder(source: &str, target: PathBuf) -> Result<String, FsError> {
    if !target.exists() {
        match create_dir_all(target.clone()) {
            Err(e) => return Err(FsError::Io(e)),
            _ => {}
        };
    }

    let mut dir_filter_map = path::PathBuf::from(source)
        .read_dir()?
        .filter_map(|entry| entry.ok());

    copy_files(
        &mut dir_filter_map,
        PathBuf::from(source),
        target.to_str().unwrap(),
    )?;
    Ok(target.to_str().unwrap().to_string())
}

fn copy_files(
    dir: &mut dyn Iterator<Item = DirEntry>,
    src_dir: PathBuf,
    target_dir: &str,
) -> Result<(), FsError> {
    let mut buffer = Vec::new();
    let target_dir = Path::new(target_dir);
    for entry in dir {
        let path = entry.path();
        let name = path.strip_prefix(Path::new(&src_dir)).unwrap();
        let new_path = target_dir.join(name);
        if path.is_file() {
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(new_path)?;

            let mut f = File::open(path)?;
            f.read_to_end(&mut buffer)?;
            file.write_all(&buffer)?;
            buffer.clear();
        } else {
            create_dir_all(new_path.clone())?;
            let mut sub_dir_filter = new_path.read_dir()?.filter_map(|entry| entry.ok());
            copy_files(&mut sub_dir_filter, path, new_path.to_str().unwrap())?;
        }
    }
    Ok(())
}

pub fn validate_function_directory_structure() -> Result<bool, FsError> {
    let dir = get_current_dir()?;

    let toml = dir.clone().join("function.toml");

    Ok(toml.is_file())
}

pub fn zip_current_directory(name: &str, tmp_dir: &Path) -> Result<PathBuf, FsError> {
    let dir = get_current_dir()?;
    let destination = tmp_dir.join(format!("{}.zip", name));
    let target_file = std::fs::OpenOptions::new()
        .create(!destination.exists())
        .read(true)
        .write(true)
        .open(&destination)
        .map_err(|e| FsError::Io(e))?;

    let mut dir_filter_map = dir.read_dir()?.filter_map(|entry| entry.ok());

    let mut zip = zip::ZipWriter::new(target_file);

    walk_dir(
        &mut dir_filter_map,
        dir.to_str().unwrap(),
        &mut zip,
        zip::CompressionMethod::Stored,
    )?;
    Ok(destination)
}

fn walk_dir(
    dir: &mut dyn Iterator<Item = DirEntry>,
    src_dir: &str,
    zip: &mut zip::ZipWriter<File>,
    method: zip::CompressionMethod,
) -> Result<(), FsError> {
    let options = FileOptions::default()
        .compression_method(method)
        .unix_permissions(0o755);

    let mut buffer = Vec::new();
    for entry in dir {
        let path = entry.path();
        let name = path.strip_prefix(Path::new(src_dir)).unwrap();
        let name_str = name.to_str().unwrap();

        if path.is_file() {
            zip.start_file(name_str, options)
                .map_err(|e| FsError::Io(std::io::Error::from(e)))?;
            let mut f = File::open(path.clone())?;
            f.read_to_end(&mut buffer)?;
            zip.write_all(&*buffer)
                .map_err(|e| FsError::Io(std::io::Error::from(e)))?;
            buffer.clear();
        } else if name.as_os_str().len() != 0 {
            let mut dir_filter_map =
                std::fs::read_dir(path.clone())?.filter_map(|entry| entry.ok());
            walk_dir(&mut dir_filter_map, src_dir, zip, method)?;
        }
    }
    Ok(())
}

pub fn get_file_for_path(path: &PathBuf) -> Option<File> {
    if !path.is_file() {
        None
    } else {
        File::open(path).ok()
    }
}

pub fn read_file_to_string(path: &String) -> Option<String> {
    let path = get_current_dir().ok()?.join(path);

    let file = File::open(&path).ok()?;
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents).ok()?;

    Some(contents)
}
