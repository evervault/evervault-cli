mod error;
use error::BuildError;

use crate::common::{resolve_output_path, OutputPath};
use crate::config::ValidatedCageBuildConfig;
use crate::docker::error::DockerError;
use crate::docker::parse::{Directive, DockerfileDecoder, Mode};
use crate::docker::utils::verify_docker_is_running;
use crate::enclave;
use std::io::Write;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncRead;

const EV_USER_DOCKERFILE_PATH: &str = "ev-user.Dockerfile";
const USER_ENTRYPOINT_SERVICE_PATH: &str = "/etc/service/user-entrypoint";
const DATA_PLANE_SERVICE_PATH: &str = "/etc/service/data-plane";

pub async fn build_enclave_image_file(
    cage_config: &ValidatedCageBuildConfig,
    context_path: &str,
    output_dir: Option<&str>,
    verbose: bool,
) -> Result<(enclave::BuiltEnclave, OutputPath), BuildError> {
    if !Path::new(&context_path).exists() {
        log::error!(
            "The build context directory {} does not exist.",
            &context_path
        );
        return Err(BuildError::ContextDirectoryDoesNotExist(
            context_path.to_string(),
        ));
    }

    // temporary directory must remain in scope for the whole
    // function so it isn't deleted until all the builds are finished.
    let output_path = resolve_output_path(output_dir)?;

    let signing_info = enclave::EnclaveSigningInfo::try_from(cage_config.signing_info())?;

    if !verify_docker_is_running()? {
        return Err(DockerError::DaemonNotRunning.into());
    }

    // read dockerfile
    let dockerfile_path = Path::new(cage_config.dockerfile());
    if !dockerfile_path.exists() {
        return Err(BuildError::DockerfileAccessError(
            cage_config.dockerfile().to_string(),
        ));
    }

    let dockerfile = File::open(dockerfile_path)
        .await
        .map_err(|_| BuildError::DockerfileAccessError(cage_config.dockerfile().to_string()))?;

    let processed_dockerfile =
        process_dockerfile(&cage_config, dockerfile, cage_config.egress().is_enabled()).await?;

    // write new dockerfile to fs
    let ev_user_dockerfile_path = output_path.join(Path::new(EV_USER_DOCKERFILE_PATH));
    let mut ev_user_dockerfile = std::fs::File::create(&ev_user_dockerfile_path)
        .map_err(|fs_err| BuildError::FailedToWriteCageDockerfile(fs_err))?;

    processed_dockerfile.iter().for_each(|instruction| {
        writeln!(ev_user_dockerfile, "{}", instruction).unwrap();
    });

    log::debug!(
        "Processed dockerfile saved at {}.",
        ev_user_dockerfile_path.display()
    );

    log::info!("Building docker image…");
    enclave::build_user_image(&ev_user_dockerfile_path, &context_path, verbose)
        .map_err(|e| BuildError::DockerBuildError(e))?;

    log::debug!("Building Nitro CLI image…");

    enclave::build_nitro_cli_image(output_path.path(), Some(&signing_info), verbose)
        .map_err(|e| BuildError::DockerBuildError(e))?;

    log::info!("Converting docker image to EIF…");
    enclave::run_conversion_to_enclave(output_path.path(), verbose)
        .map(|built_enc| (built_enc, output_path))
        .map_err(|e| BuildError::EnclaveConversionError(e))
}

async fn process_dockerfile<R: AsyncRead + std::marker::Unpin>(
    build_config: &ValidatedCageBuildConfig,
    dockerfile_src: R,
    enable_egress: bool,
) -> Result<Vec<Directive>, BuildError> {
    // Decode dockerfile from file
    let instruction_set = DockerfileDecoder::decode_dockerfile_from_src(dockerfile_src).await?;

    // Filter out unwanted directives
    let mut last_cmd = None;
    let mut last_entrypoint = None;
    let mut exposed_port: Option<u16> = None;

    let remove_unwanted_directives = |directive: &Directive| -> bool {
        if directive.is_cmd() {
            last_cmd = Some(directive.clone());
        } else if directive.is_entrypoint() {
            last_entrypoint = Some(directive.clone());
        } else if let Directive::Expose { port } = directive {
            exposed_port = *port;
        } else {
            return true;
        }
        false
    };

    let cleaned_instructions: Vec<Directive> = instruction_set
        .into_iter()
        .filter(remove_unwanted_directives)
        .collect();

    let user_service_builder = crate::docker::utils::create_combined_docker_entrypoint(
        last_entrypoint,
        last_cmd,
    )
    .map(|entrypoint| {
        let entrypoint_script = format!("echo \"Booting user service...\"\\n{}", entrypoint);
        let user_service_runner = format!("{USER_ENTRYPOINT_SERVICE_PATH}/run");
        let user_service_builder_script = crate::docker::utils::write_command_to_script(
            entrypoint_script.as_str(),
            user_service_runner.as_str(),
        );
        Directive::new_run(user_service_builder_script)
    })?;

    if let Some(true) = exposed_port.map(|port| port == 443) {
        return Err(DockerError::RestrictedPortExposed(exposed_port.unwrap()).into());
    }

    let data_plane_feature_label = if enable_egress {
        "egress-enabled"
    } else {
        "egress-disabled"
    };

    #[cfg(not(debug_assertions))]
  let data_plane_url = format!("https://cage-build-assets.evervault.com/runtime/latest/data-plane/{data_plane_feature_label}");
    #[cfg(debug_assertions)]
  let data_plane_url = format!("https://cage-build-assets.evervault.io/runtime/latest/data-plane/{data_plane_feature_label}");

    let mut data_plane_run_script =
        r#"echo "Booting Evervault data plane..."\nexec /data-plane"#.to_string();
    if let Some(port) = exposed_port {
        data_plane_run_script = format!("{data_plane_run_script} -p {port}");
    }

    let bootstrap_script_content = if enable_egress {
        r#"ifconfig lo 127.0.0.1\necho "Booting enclave..."\nexec runsvdir /etc/service"#
    } else {
        r#"echo "Booting enclave..."\nexec runsvdir /etc/service"#
    };

    let injected_directives = vec![
        // install dependencies
        Directive::new_run(crate::docker::utils::write_command_to_script(
            r#"if command -v apk &> /dev/null\nthen\necho "Installing using apk"\napk update ; apk add net-tools runit ; rm -rf /var/cache/apk/*\nelif\ncommand -v apt-get &>/dev/null\nthen\necho "Installing using apt-get"\napt-get upgrade ; apt-get update ; apt-get -y install net-tools runit ; apt-get clean ; rm -rf /var/lib/apt/lists/*\nelse\necho "No suitable installer found. Please contact support: support@evervault.com"\nexit 1\nfi"#,
            "/runtime-installer",
        )),
        Directive::new_run("sh /runtime-installer ; rm /runtime-installer"),
        // create user service directory
        Directive::new_run(format!("mkdir -p {USER_ENTRYPOINT_SERVICE_PATH}")),
        // add user service runner
        user_service_builder,
        // add data-plane executable
        Directive::new_run(format!(
            "wget {data_plane_url} -O /data-plane && chmod +x /data-plane"
        )),
        // add data-plane service directory
        Directive::new_run(format!("mkdir -p {DATA_PLANE_SERVICE_PATH}")),
        // add data-plane service runner
        Directive::new_run(crate::docker::utils::write_command_to_script(
            data_plane_run_script.as_str(),
            format!("{DATA_PLANE_SERVICE_PATH}/run").as_str(),
        )),
        // set cage name and app uuid as in enclave env vars
        Directive::new_env("EV_CAGE_NAME", build_config.cage_name()),
        Directive::new_env("EV_APP_UUID", build_config.app_uuid()),
        // Add bootstrap script to configure enclave before starting services
        Directive::new_run(crate::docker::utils::write_command_to_script(
            bootstrap_script_content,
            "/bootstrap",
        )),
        // add entrypoint which starts the runit services
        Directive::new_entrypoint(
            Mode::Exec,
            vec!["/bootstrap".to_string(), "1>&2".to_string()],
        ),
    ];

    // add custom directives to end of dockerfile
    Ok([cleaned_instructions, injected_directives].concat())
}

#[cfg(test)]
mod test {
    use super::{build_enclave_image_file, process_dockerfile, BuildError};
    use crate::config::EgressSettings;
    use crate::config::ValidatedCageBuildConfig;
    use crate::config::ValidatedSigningInfo;
    use crate::docker;
    use crate::enclave;
    use itertools::zip;
    use tempfile::TempDir;

    fn get_config() -> ValidatedCageBuildConfig {
        ValidatedCageBuildConfig {
            cage_name: "test".into(),
            cage_uuid: "1234".into(),
            debug: false,
            app_uuid: "3241".into(),
            dockerfile: "".into(),
            egress: EgressSettings {
                enabled: false,
                destinations: None,
            },
            attestation: None,
            signing: ValidatedSigningInfo {
                cert: "".into(),
                key: "".into(),
            },
        }
    }

    #[tokio::test]
    async fn test_process_dockerfile() {
        let sample_dockerfile_contents = r#"FROM alpine

RUN touch /hello-script;\
    /bin/sh -c "echo -e '"'#!/bin/sh\nwhile true; do echo "hello"; sleep 2; done;\n'"' > /hello-script"

ENTRYPOINT ["sh", "/hello-script"]"#;
        let mut readable_contents = sample_dockerfile_contents.as_bytes();

        let config = get_config();

        let processed_file = process_dockerfile(&config, &mut readable_contents, false).await;
        assert_eq!(processed_file.is_ok(), true);
        let processed_file = processed_file.unwrap();

        let expected_output_contents = r#"FROM alpine
RUN touch /hello-script;\
    /bin/sh -c "echo -e '"'#!/bin/sh\nwhile true; do echo "hello"; sleep 2; done;\n'"' > /hello-script"
RUN /bin/sh -c "printf '"'#!/bin/sh\nif command -v apk &> /dev/null\nthen\necho "Installing using apk"\napk update ; apk add net-tools runit ; rm -rf /var/cache/apk/*\nelif\ncommand -v apt-get &>/dev/null\nthen\necho "Installing using apt-get"\napt-get upgrade ; apt-get update ; apt-get -y install net-tools runit ; apt-get clean ; rm -rf /var/lib/apt/lists/*\nelse\necho "No suitable installer found. Please contact support: support@evervault.com"\nexit 1\nfi\n'"' > /runtime-installer" && chmod +x /runtime-installer
RUN sh /runtime-installer ; rm /runtime-installer
RUN mkdir -p /etc/service/user-entrypoint
RUN /bin/sh -c "printf '"'#!/bin/sh\necho "Booting user service..."\nsh /hello-script\n'"' > /etc/service/user-entrypoint/run" && chmod +x /etc/service/user-entrypoint/run
RUN wget https://cage-build-assets.evervault.io/runtime/latest/data-plane/egress-disabled -O /data-plane && chmod +x /data-plane
RUN mkdir -p /etc/service/data-plane
RUN /bin/sh -c "printf '"'#!/bin/sh\necho "Booting Evervault data plane..."\nexec /data-plane\n'"' > /etc/service/data-plane/run" && chmod +x /etc/service/data-plane/run
ENV EV_CAGE_NAME=test
ENV EV_APP_UUID=3241
RUN /bin/sh -c "printf '"'#!/bin/sh\necho "Booting enclave..."\nexec runsvdir /etc/service\n'"' > /bootstrap" && chmod +x /bootstrap
ENTRYPOINT ["/bootstrap", "1>&2"]
"#;

        let expected_directives = docker::parse::DockerfileDecoder::decode_dockerfile_from_src(
            expected_output_contents.as_bytes(),
        )
        .await
        .unwrap();

        assert_eq!(expected_directives.len(), processed_file.len());
        for (expected_directive, processed_directive) in
            zip(expected_directives.iter(), processed_file.iter())
        {
            assert_eq!(
                expected_directive.to_string(),
                processed_directive.to_string()
            );
        }
    }

    #[tokio::test]
    async fn test_process_dockerfile_with_restricted_reserved_port() {
        let sample_dockerfile_contents = r#"FROM alpine

RUN touch /hello-script;\
    /bin/sh -c "echo -e '"'#!/bin/sh\nwhile true; do echo "hello"; sleep 2; done;\n'"' > /hello-script"
EXPOSE 443
ENTRYPOINT ["sh", "/hello-script"]"#;
        let mut readable_contents = sample_dockerfile_contents.as_bytes();

        let config = get_config();

        let processed_file = process_dockerfile(&config, &mut readable_contents, false).await;
        assert_eq!(processed_file.is_err(), true);

        assert!(matches!(
            processed_file,
            Err(BuildError::DockerError(
                crate::docker::error::DockerError::RestrictedPortExposed(443)
            ))
        ));
    }

    #[tokio::test]
    async fn test_process_dockerfile_with_valid_reserved_port() {
        let sample_dockerfile_contents = r#"FROM alpine

RUN touch /hello-script;\
    /bin/sh -c "echo -e '"'#!/bin/sh\nwhile true; do echo "hello"; sleep 2; done;\n'"' > /hello-script"
EXPOSE 3443
ENTRYPOINT ["sh", "/hello-script"]"#;
        let mut readable_contents = sample_dockerfile_contents.as_bytes();

        let config = get_config();

        let processed_file = process_dockerfile(&config, &mut readable_contents, false).await;
        assert_eq!(processed_file.is_ok(), true);
        let processed_file = processed_file.unwrap();

        let expected_output_contents = r#"FROM alpine
RUN touch /hello-script;\
    /bin/sh -c "echo -e '"'#!/bin/sh\nwhile true; do echo "hello"; sleep 2; done;\n'"' > /hello-script"
RUN /bin/sh -c "printf '"'#!/bin/sh\nif command -v apk &> /dev/null\nthen\necho "Installing using apk"\napk update ; apk add net-tools runit ; rm -rf /var/cache/apk/*\nelif\ncommand -v apt-get &>/dev/null\nthen\necho "Installing using apt-get"\napt-get upgrade ; apt-get update ; apt-get -y install net-tools runit ; apt-get clean ; rm -rf /var/lib/apt/lists/*\nelse\necho "No suitable installer found. Please contact support: support@evervault.com"\nexit 1\nfi\n'"' > /runtime-installer" && chmod +x /runtime-installer
RUN sh /runtime-installer ; rm /runtime-installer
RUN mkdir -p /etc/service/user-entrypoint
RUN /bin/sh -c "printf '"'#!/bin/sh\necho "Booting user service..."\nsh /hello-script\n'"' > /etc/service/user-entrypoint/run" && chmod +x /etc/service/user-entrypoint/run
RUN wget https://cage-build-assets.evervault.io/runtime/latest/data-plane/egress-disabled -O /data-plane && chmod +x /data-plane
RUN mkdir -p /etc/service/data-plane
RUN /bin/sh -c "printf '"'#!/bin/sh\necho "Booting Evervault data plane..."\nexec /data-plane -p 3443\n'"' > /etc/service/data-plane/run" && chmod +x /etc/service/data-plane/run
ENV EV_CAGE_NAME=test
ENV EV_APP_UUID=3241
RUN /bin/sh -c "printf '"'#!/bin/sh\necho "Booting enclave..."\nexec runsvdir /etc/service\n'"' > /bootstrap" && chmod +x /bootstrap
ENTRYPOINT ["/bootstrap", "1>&2"]
"#;

        let expected_directives = docker::parse::DockerfileDecoder::decode_dockerfile_from_src(
            expected_output_contents.as_bytes(),
        )
        .await
        .unwrap();

        assert_eq!(expected_directives.len(), processed_file.len());
        for (expected_directive, processed_directive) in
            zip(expected_directives.iter(), processed_file.iter())
        {
            assert_eq!(
                expected_directive.to_string(),
                processed_directive.to_string()
            );
        }
    }

    #[tokio::test]
    async fn test_choose_output_dir() {
        let output_dir = TempDir::new().unwrap();

        crate::cli::cert::create_new_cert(crate::cli::cert::NewCertArgs {
            subject: "/CN=EV/C=IE/ST=LEI/L=DUB/O=Evervault/OU=Eng".into(),
            output_dir: ".".into(),
        });

        let build_args = ValidatedCageBuildConfig {
            cage_name: "test-cage".into(),
            cage_uuid: "1234".into(),
            app_uuid: "4321".into(),
            debug: false,
            egress: EgressSettings {
                enabled: false,
                destinations: None,
            },
            dockerfile: "./sample-user.Dockerfile".to_string(),
            signing: ValidatedSigningInfo {
                cert: "./cert.pem".into(),
                key: "./key.pem".into(),
            },
            attestation: None,
        };

        println!(
            "output_dir: {}",
            output_dir.path().to_str().unwrap().to_string()
        );

        let _ = build_enclave_image_file(
            &build_args,
            ".",
            Some(output_dir.path().to_str().unwrap()),
            false,
        )
        .await;

        let paths = std::fs::read_dir(output_dir.path().to_str().unwrap().to_string()).unwrap();

        for path in paths {
            println!("Name: {}", path.unwrap().path().display())
        }

        assert_eq!(
            output_dir
                .path()
                .join(super::EV_USER_DOCKERFILE_PATH)
                .exists(),
            true
        );
        assert_eq!(
            output_dir
                .path()
                .join(enclave::NITRO_CLI_IMAGE_FILENAME)
                .exists(),
            true
        );
        assert_eq!(
            output_dir.path().join(enclave::ENCLAVE_FILENAME).exists(),
            true
        );
    }
}
