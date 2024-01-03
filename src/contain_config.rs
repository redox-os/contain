use std::{
    fs::{self, File},
    io::Error,
    path::Path,
};

use log::{debug, error};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ContainConfig {
    /// Optional root directory for chroot
    /// Not normally specified in the config file
    pub root: Option<String>,
    /// schemes that are are allowed, and handled elsewhere
    pub pass_schemes: Vec<String>,
    /// schemes that are managed by this instance of contain
    pub sandbox_schemes: Vec<String>,
    /// exact match files and paths to allow
    pub files: Vec<String>,
    /// directories and prefixes to allow
    pub dirs: Vec<String>,
    /// readonly files
    pub rofiles: Vec<String>,
    /// directories with readonly contents
    pub rodirs: Vec<String>,
}

impl ContainConfig {
    /// Create a config with sensible defaults
    pub fn use_defaults() -> Self {
        fn to_string_vec(a: &[&str]) -> Vec<String> {
            let mut v = vec![];
            for s in a {
                v.push(s.to_string());
            }
            v
        }

        Self {
            root: None,
            pass_schemes: to_string_vec(&["rand", "null", "tcp", "udp", "thisproc"]),
            sandbox_schemes: to_string_vec(&["file"]),
            files: to_string_vec(&["file:/dev/null"]),
            dirs: to_string_vec(&["file:/bin"]),
            rofiles: to_string_vec(&["file:/etc/passwd", "file:/etc/hostname", "file:/tmp"]),
            rodirs: to_string_vec(&["file:/bin"]),
        }
    }

    /// Deserialize the config from a file
    pub fn from_file(filename: &str) -> Result<Self, Error> {
        let config_file = Path::new(filename);
        let config: ContainConfig = match config_file.extension() {
            Some(ext) if ext == "ron" => {
                debug!("reading .ron config from {:?}", config_file);
                let config_fd = File::open(config_file).map_err(|e| {
                    error!(
                        "Contain: could not open .ron config file {:?}, {}",
                        config_file, e
                    );
                    e
                })?;
                ron::de::from_reader(config_fd).map_err(|e| {
                    error!("Contain: serializing .ron config, {}: {}", filename, e);
                    Error::other(format!("{}", e))
                })?
            }
            Some(ext) if ext == "toml" => {
                debug!("reading .toml config from {:?}", config_file);
                let config_str = fs::read_to_string(config_file).map_err(|e| {
                    error!(
                        "Contain: could not open .toml config file {:?}, {}",
                        config_file, e
                    );
                    e
                })?;
                toml::from_str(&config_str).map_err(|e| {
                    error!("serializing failed, {}: {}", filename, e);
                    Error::other(format!("serializing failed, {}: {}", filename, e))
                })?
            }
            Some(_) | None => {
                error!("config filename must end in .toml or .ron");
                return Err(Error::other(format!(
                    "filename must end in .toml or .ron: {}",
                    filename
                )));
            }
        };

        debug!("config: {:?}", config);

        Ok(config)
    }

    pub fn add_chroot(&mut self, root: &str) {
        self.root = Some(root.to_string());
    }

    pub fn add_dir(&mut self, dir: &str) {
        self.dirs.push(dir.to_string());
    }

    pub fn add_rodir(&mut self, rodir: &str) {
        self.rodirs.push(rodir.to_string());
    }
}
