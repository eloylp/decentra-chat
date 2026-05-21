use serde::{Deserialize, Serialize};
use std::{
    env,
    fs,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use thiserror::Error;

pub const DEFAULT_MULTICAST_GROUP: IpAddr = IpAddr::V4(Ipv4Addr::new(239, 255, 40, 91));
pub const DEFAULT_DISCOVERY_PORT: u16 = 40091;
pub const DEFAULT_LISTEN_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const DEFAULT_STORAGE_FILE: &str = "decentra-chat.sqlite3";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub multicast_group: IpAddr,
    pub discovery_port: u16,
    pub listen_addr: IpAddr,
    pub storage_path: PathBuf,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse TOML config file at {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid config field `{field}`: {message}")]
    InvalidField {
        field: &'static str,
        message: String,
    },
}

impl Config {
    pub fn load() -> Result<Arc<Self>, ConfigError> {
        Self::load_from_path(default_config_path()).map(Arc::new)
    }

    pub fn load_shared() -> Result<Arc<Self>, ConfigError> {
        Self::load()
    }

    pub fn load_shared_from_path(path: impl AsRef<Path>) -> Result<Arc<Self>, ConfigError> {
        Self::load_from_path(path).map(Arc::new)
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();

        if !path.exists() {
            return Self::default().validate();
        }

        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        let file_config: FileConfig =
            toml::from_str(&contents).map_err(|source| ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            })?;

        file_config
            .into_config(Self::default())?
            .validate()
    }

    pub fn default_storage_path() -> PathBuf {
        default_config_dir().join(DEFAULT_STORAGE_FILE)
    }

    fn validate(self) -> Result<Self, ConfigError> {
        if self.discovery_port == 0 {
            return Err(ConfigError::InvalidField {
                field: "discovery_port",
                message: "must be between 1 and 65535".to_owned(),
            });
        }

        if self.storage_path.as_os_str().is_empty() {
            return Err(ConfigError::InvalidField {
                field: "storage_path",
                message: "must not be empty".to_owned(),
            });
        }

        Ok(self)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            multicast_group: DEFAULT_MULTICAST_GROUP,
            discovery_port: DEFAULT_DISCOVERY_PORT,
            listen_addr: DEFAULT_LISTEN_ADDR,
            storage_path: Self::default_storage_path(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    multicast_group: Option<String>,
    discovery_port: Option<u16>,
    listen_addr: Option<String>,
    storage_path: Option<PathBuf>,
}

impl FileConfig {
    fn into_config(self, defaults: Config) -> Result<Config, ConfigError> {
        Ok(Config {
            multicast_group: parse_ip_field(
                "multicast_group",
                self.multicast_group,
                defaults.multicast_group,
            )?,
            discovery_port: self.discovery_port.unwrap_or(defaults.discovery_port),
            listen_addr: parse_ip_field("listen_addr", self.listen_addr, defaults.listen_addr)?,
            storage_path: self.storage_path.unwrap_or(defaults.storage_path),
        })
    }
}

fn parse_ip_field(
    field: &'static str,
    value: Option<String>,
    default: IpAddr,
) -> Result<IpAddr, ConfigError> {
    let Some(value) = value else {
        return Ok(default);
    };

    IpAddr::from_str(&value).map_err(|_| ConfigError::InvalidField {
        field,
        message: "must be a valid IP address".to_owned(),
    })
}

pub fn default_config_path() -> PathBuf {
    env::var_os("DC_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_config_dir().join("config.toml"))
}

fn default_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(".config"))
        .join("decentra-chat")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_config_file_loads_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");

        let config = Config::load_from_path(&config_path).expect("missing file should load");

        assert_eq!(config.multicast_group, DEFAULT_MULTICAST_GROUP);
        assert_eq!(config.discovery_port, DEFAULT_DISCOVERY_PORT);
        assert_eq!(config.listen_addr, DEFAULT_LISTEN_ADDR);
        assert_eq!(config.storage_path, Config::default_storage_path());
    }

    #[test]
    fn explicit_values_override_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage_path = dir.path().join("chat.db");
        let config_path = dir.path().join("config.toml");
        fs::write(
            &config_path,
            format!(
                r#"
multicast_group = "239.255.40.92"
discovery_port = 41000
listen_addr = "127.0.0.1"
storage_path = "{}"
"#,
                storage_path.display()
            ),
        )
        .expect("write config");

        let config = Config::load_from_path(&config_path).expect("config should load");

        assert_eq!(
            config.multicast_group,
            IpAddr::V4(Ipv4Addr::new(239, 255, 40, 92))
        );
        assert_eq!(config.discovery_port, 41000);
        assert_eq!(config.listen_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(config.storage_path, storage_path);
    }

    #[test]
    fn invalid_port_returns_actionable_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        fs::write(&config_path, "discovery_port = 0\n").expect("write config");

        let error = Config::load_from_path(&config_path).expect_err("port 0 is invalid");

        assert!(matches!(
            error,
            ConfigError::InvalidField {
                field: "discovery_port",
                ..
            }
        ));
        assert!(error.to_string().contains("discovery_port"));
    }

    #[test]
    fn malformed_ip_names_parse_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        fs::write(&config_path, "multicast_group = \"not an ip\"\n").expect("write config");

        let error = Config::load_from_path(&config_path).expect_err("ip is invalid");

        assert!(matches!(
            error,
            ConfigError::InvalidField {
                field: "multicast_group",
                ..
            }
        ));
        assert!(error.to_string().contains("multicast_group"));
    }

    #[test]
    fn config_round_trips_through_toml() {
        let config = Config {
            multicast_group: IpAddr::V4(Ipv4Addr::new(239, 255, 40, 91)),
            discovery_port: 40091,
            listen_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            storage_path: PathBuf::from("state/chat.sqlite3"),
        };

        let toml = toml::to_string(&config).expect("serialize config");
        let decoded: Config = toml::from_str(&toml).expect("deserialize config");

        assert_eq!(decoded, config);
    }

    #[test]
    fn load_shared_returns_arc_config() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");

        let config = Config::load_shared_from_path(&config_path).expect("load config");

        assert_eq!(Arc::strong_count(&config), 1);
        assert_eq!(config.discovery_port, DEFAULT_DISCOVERY_PORT);
    }
}
