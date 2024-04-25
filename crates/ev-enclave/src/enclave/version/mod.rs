use crate::enclave::{api::assets::AssetsClient, api::client::ApiError, common::CliError};
use chrono::Utc;
use regex::Regex;
use semver::Version;
use std::env;
use std::fs;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VersionError {
    #[error("An error occurred getting CLI versions — {0}")]
    ApiError(#[from] ApiError),
    #[error("Couldn't parse the semver version - {0}")]
    SemVerError(#[from] semver::Error),
    #[error("Couldn't parse env string as int - {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("This version is deprecated, please run ev-enclave update to continue")]
    DeprecatedVersion,
    #[error("Couldn't check version against latest")]
    FailedVersionCheck,
    #[error("IO error - {0}")]
    IoError(#[from] std::io::Error),
    #[error("Regex error - {0}")]
    RegexError(#[from] regex::Error),
    #[error("Couldn't find the runtime and installer version in the Dockerfile")]
    MissingVersion,
}

impl CliError for VersionError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::IoError(_) => exitcode::IOERR,
            _ => exitcode::SOFTWARE,
        }
    }
}

pub fn get_latest_major_version() -> Result<u8, VersionError> {
    Ok(env!("CARGO_PKG_VERSION_MAJOR").parse::<u8>()?)
}

pub async fn check_version() -> Result<(), VersionError> {
    if std::env::var("EV_DOMAIN").unwrap_or_else(|_| String::from("evervault.com"))
        == "evervault.io"
    {
        return Ok(());
    }
    match alert_on_deprecation().await? {
        Some(_) => Err(VersionError::DeprecatedVersion),
        _ => Ok(()),
    }
}

async fn alert_on_deprecation() -> Result<Option<i64>, VersionError> {
    let assets_client = AssetsClient::new();
    let version_info = assets_client.get_cli_versions().await?;
    let installed_major_version = get_latest_major_version()?;
    let installed_semver = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let current_version = match version_info
        .versions
        .get(&installed_major_version.to_string())
    {
        Some(version) => version,
        None => return Err(VersionError::FailedVersionCheck),
    };
    let latest_semver = Version::parse(current_version.latest.as_str())?;
    if let Some(deprecation_date) = &current_version.deprecation_date {
        let current_time = Utc::now().timestamp();
        if current_time > deprecation_date.parse::<i64>()? {
            return Ok(Some(deprecation_date.parse::<i64>()?));
        } else {
            log::warn!(
                "This major version will be deprecated on {}",
                deprecation_date
            );
        }
    } else if installed_semver < latest_semver {
        log::warn!(
            "You are behind the latest version. Installed version: {}, latest version {}",
            installed_semver,
            latest_semver
        );
    }
    Ok(None)
}

pub async fn get_runtime_and_installer_version(
    from_existing: Option<String>,
) -> Result<(String, String), VersionError> {
    match from_existing {
        Some(existing) => parse_version_from_existing_dockerfile(existing),
        None => {
            let enclave_build_assets_client = AssetsClient::new();
            let data_plane_version = enclave_build_assets_client.get_data_plane_version().await?;
            let installer_version = enclave_build_assets_client.get_installer_version().await?;
            Ok((data_plane_version, installer_version))
        }
    }
}

pub fn parse_version_from_existing_dockerfile(
    from_existing: String,
) -> Result<(String, String), VersionError> {
    let content = fs::read_to_string(from_existing)?;
    get_versions_from_dockerfile(content)
}

fn get_versions_from_dockerfile(content: String) -> Result<(String, String), VersionError> {
    let installer_regex = Regex::new(r"installer\/([a-f0-9]+)\.tar\.gz")?;
    let runtime_regex = Regex::new(r"runtime\/(.*?)\/data-plane")?;
    let installer_version = installer_regex
        .captures(&content)
        .and_then(|mtch| mtch.get(1).map(|m| m.as_str()))
        .ok_or(VersionError::MissingVersion)?;
    let runtime_version = runtime_regex
        .captures(&content)
        .and_then(|mtch| mtch.get(1).map(|m| m.as_str()))
        .ok_or(VersionError::MissingVersion)?;

    Ok((runtime_version.to_string(), installer_version.to_string()))
}

#[cfg(test)]
mod versions_tests {
    use super::*;

    #[test]
    fn parse_version_from_existing_dockerfile() {
        let test_dockerfile = r##"FROM node:18-alpine AS builder
        # Do stuff
        FROM alpine AS lastlayer
        RUN touch /hello-script;\
        /bin/sh -c "echo -e '"'#!/bin/sh\nwhile true; do echo "hello"; sleep 2; done;\n'"' > /hello-script"
        USER root
        RUN mkdir -p /opt/evervault
        ADD https://enclave-build-assets.evervault.com/installer/abcdef.tar.gz /opt/evervault/runtime-dependencies.tar.gz
        RUN cd /opt/evervault ; tar -xzf runtime-dependencies.tar.gz ; sh ./installer.sh ; rm runtime-dependencies.tar.gz
        RUN echo {\"api_key_auth\":true,\"forward_proxy_protocol\":false,\"trusted_headers\":[\"X-Evervault-*\"],\"trx_logging_enabled\":true} > /etc/dataplane-config.json
        RUN mkdir -p /etc/service/user-entrypoint
        RUN printf "#!/bin/sh\nsleep 5\necho \"Checking status of data-plane\"\nSVDIR=/etc/service sv check data-plane || exit 1\necho \"Data-plane up and running\"\nwhile ! grep -q \"EV_INITIALIZED\" /etc/customer-env\n do echo \"Env not ready, sleeping user process for one second\"\n sleep 1\n done \n . /etc/customer-env\n\necho \"Booting user service...\"\ncd %s\nexec sh /hello-script\n" "$PWD"  > /etc/service/user-entrypoint/run && chmod +x /etc/service/user-entrypoint/run
        ADD https://enclave-build-assets.evervault.com/runtime/1.2.3/data-plane/egress-disabled/tls-termination-enabled /opt/evervault/data-plane
        RUN chmod +x /opt/evervault/data-plane
        RUN mkdir -p /etc/service/data-plane
        RUN printf "#!/bin/sh\necho \"Booting Evervault data plane...\"\nexec /opt/evervault/data-plane\n" > /etc/service/data-plane/run && chmod +x /etc/service/data-plane/run
        RUN printf "#!/bin/sh\nifconfig lo 127.0.0.1\n echo \"enclave.local\" > /etc/hostname \n echo \"127.0.0.1 enclave.local\" >> /etc/hosts \n hostname -F /etc/hostname \necho \"Booting enclave...\"\nexec runsvdir /etc/service\n" > /bootstrap && chmod +x /bootstrap
        RUN find $( ls / | grep -E -v "^(dev|mnt|proc|sys)$" ) -xdev | xargs touch --date="@0" --no-dereference || true
        FROM scratch
        COPY --from=lastlayer / /
        ENTRYPOINT ["/bootstrap", "1>&2"]
        "##.to_string();

        let result = get_versions_from_dockerfile(test_dockerfile).unwrap();
        assert_eq!(result, ("1.2.3".to_string(), "abcdef".to_string()));
    }

    #[test]
    fn parse_version_from_existing_dockerfile_staging() {
        let test_dockerfile = r##"FROM node:18-alpine AS builder
        # Do stuff
        FROM alpine AS lastlayer
        RUN touch /hello-script;\
        /bin/sh -c "echo -e '"'#!/bin/sh\nwhile true; do echo "hello"; sleep 2; done;\n'"' > /hello-script"
        USER root
        RUN mkdir -p /opt/evervault
        ADD https://enclave-build-assets.evervault.com/installer/abcdef.tar.gz /opt/evervault/runtime-dependencies.tar.gz
        RUN cd /opt/evervault ; tar -xzf runtime-dependencies.tar.gz ; sh ./installer.sh ; rm runtime-dependencies.tar.gz
        RUN echo {\"api_key_auth\":true,\"forward_proxy_protocol\":false,\"trusted_headers\":[\"X-Evervault-*\"],\"trx_logging_enabled\":true} > /etc/dataplane-config.json
        RUN mkdir -p /etc/service/user-entrypoint
        RUN printf "#!/bin/sh\nsleep 5\necho \"Checking status of data-plane\"\nSVDIR=/etc/service sv check data-plane || exit 1\necho \"Data-plane up and running\"\nwhile ! grep -q \"EV_INITIALIZED\" /etc/customer-env\n do echo \"Env not ready, sleeping user process for one second\"\n sleep 1\n done \n . /etc/customer-env\n\necho \"Booting user service...\"\ncd %s\nexec sh /hello-script\n" "$PWD"  > /etc/service/user-entrypoint/run && chmod +x /etc/service/user-entrypoint/run
        ADD https://enclave-build-assets.evervault.io/runtime/1.0.0-beta-daac60/data-plane/egress-disabled/tls-termination-enabled /opt/evervault/data-plane
        RUN chmod +x /opt/evervault/data-plane
        RUN mkdir -p /etc/service/data-plane
        RUN printf "#!/bin/sh\necho \"Booting Evervault data plane...\"\nexec /opt/evervault/data-plane\n" > /etc/service/data-plane/run && chmod +x /etc/service/data-plane/run
        RUN printf "#!/bin/sh\nifconfig lo 127.0.0.1\n echo \"enclave.local\" > /etc/hostname \n echo \"127.0.0.1 enclave.local\" >> /etc/hosts \n hostname -F /etc/hostname \necho \"Booting enclave...\"\nexec runsvdir /etc/service\n" > /bootstrap && chmod +x /bootstrap
        RUN find $( ls / | grep -E -v "^(dev|mnt|proc|sys)$" ) -xdev | xargs touch --date="@0" --no-dereference || true
        FROM scratch
        COPY --from=lastlayer / /
        ENTRYPOINT ["/bootstrap", "1>&2"]
        "##.to_string();

        let result = get_versions_from_dockerfile(test_dockerfile).unwrap();
        assert_eq!(
            result,
            ("1.0.0-beta-daac60".to_string(), "abcdef".to_string())
        );
    }

    #[test]
    fn parse_version_from_existing_dockerfile_error() {
        let test_dockerfile = r#"ENV Hello World Spaces"#.to_string();
        let result = get_versions_from_dockerfile(test_dockerfile);
        assert!(result.is_err())
    }
}
