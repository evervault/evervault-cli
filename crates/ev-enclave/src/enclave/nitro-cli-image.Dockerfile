FROM amazonlinux:2023


# install Nitro CLI
RUN dnf install aws-nitro-enclaves-cli -y; \
dnf install aws-nitro-enclaves-cli-devel -y;

ENTRYPOINT ["nitro-cli"]
