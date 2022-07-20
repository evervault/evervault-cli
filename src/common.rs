use std::ffi::OsStr;
use std::path::PathBuf;
use thiserror::Error;

pub struct OutputPath {
    _tmp_dir: Option<tempfile::TempDir>,
    file_path: PathBuf,
}

impl OutputPath {
    pub fn path(&self) -> &PathBuf {
        &self.file_path
    }

    pub fn join(&self, path: &std::path::Path) -> PathBuf {
        self.file_path.join(path)
    }
}

impl std::convert::From<PathBuf> for OutputPath {
    fn from(value: PathBuf) -> Self {
        Self {
            _tmp_dir: None,
            file_path: value,
        }
    }
}

impl std::convert::From<tempfile::TempDir> for OutputPath {
    fn from(value: tempfile::TempDir) -> Self {
        let tmp_path = value.path().to_path_buf();
        Self {
            _tmp_dir: Some(value),
            file_path: tmp_path,
        }
    }
}

#[derive(Debug, Error)]
pub enum OutputPathError {
    #[error("The directory provided does not exist.")]
    PathDoesNotExist,
    #[error("Failed to get absolute path — {0:?}")]
    FailedToGetAbsolutePath(#[from] std::io::Error),
    #[error("Failed to create temp dir — {0:?}")]
    FailedToCreateTempDir(std::io::Error),
}

pub fn resolve_output_path(
    supplied_path: Option<impl AsRef<OsStr>>,
) -> Result<OutputPath, OutputPathError> {
    if let Some(output_dir) = supplied_path {
        let path = std::path::Path::new(&output_dir);
        let absolute_path = path.canonicalize().map(OutputPath::from)?;
        Ok(absolute_path)
    } else {
        let temp_dir = tempfile::TempDir::new().map_err(OutputPathError::FailedToCreateTempDir)?;
        Ok(OutputPath::from(temp_dir))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_resolve_output_path_with_no_path_given() {
        let path: Option<&str> = None;
        let output_path = resolve_output_path(path).expect("Failed to generate temp file");
        assert!(output_path._tmp_dir.is_some());
    }

    #[test]
    fn test_resolve_output_path_with_path_given() {
        let output_path =
            resolve_output_path(Some("./src")).expect("Failed to resolve canonical path");
        assert!(output_path._tmp_dir.is_none());
        assert!(output_path.file_path.as_path().ends_with("src"));
    }
}
