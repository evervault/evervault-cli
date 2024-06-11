use std::fs::{create_dir_all, DirEntry, File};
use std::io::Error as IoError;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zip::{self, write::SimpleFileOptions};

pub fn extract_zip(tmpfile: File, target_dir: &PathBuf) -> Result<String, IoError> {
    let mut zip = zip::ZipArchive::new(tmpfile).unwrap();

    if !target_dir.exists() {
        create_dir_all(target_dir.clone())?;
    }

    zip.extract(&target_dir)
        .map(|_| target_dir.to_str().unwrap().to_string())
        .map_err(|e| std::io::Error::from(e))
}

pub fn copy_folder(source: &PathBuf, target: &PathBuf) -> Result<String, IoError> {
    if !target.exists() {
        create_dir_all(target.clone())?
    }

    let mut dir_filter_map = source.read_dir()?.filter_map(|entry| entry.ok());

    copy_files(&mut dir_filter_map, source, target)?;
    Ok(target.to_str().unwrap().to_string())
}

fn copy_files(
    dir: &mut dyn Iterator<Item = DirEntry>,
    src_dir: &PathBuf,
    target_dir: &PathBuf,
) -> Result<(), IoError> {
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
            copy_files(&mut sub_dir_filter, &path, &new_path)?;
        }
    }
    Ok(())
}

pub fn zip_current_directory(name: &str, tmp_dir: &Path) -> Result<PathBuf, IoError> {
    let dir = std::env::current_dir()?;
    let destination = tmp_dir.join(format!("{}.zip", name));
    let target_file = std::fs::OpenOptions::new()
        .create(!destination.exists())
        .read(true)
        .write(true)
        .open(&destination)?;

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
) -> Result<(), IoError> {
    let options = SimpleFileOptions::default()
        .compression_method(method)
        .unix_permissions(0o755);

    let mut buffer = Vec::new();
    for entry in dir {
        let path = entry.path();
        let name = path.strip_prefix(Path::new(src_dir)).unwrap();
        let name_str = name.to_str().unwrap();

        if path.is_file() {
            zip.start_file(name_str, options)?;

            let mut f = File::open(path.clone())?;
            f.read_to_end(&mut buffer)?;
            zip.write_all(&*buffer)?;
            buffer.clear();
        } else if name.as_os_str().len() != 0 {
            let mut dir_filter_map =
                std::fs::read_dir(path.clone())?.filter_map(|entry| entry.ok());
            walk_dir(&mut dir_filter_map, src_dir, zip, method)?;
        }
    }
    Ok(())
}
