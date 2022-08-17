# Cages CLI

Build, deploy and manage Cages

## Run Locally against staging

```
> export EV_API_URL=https://internal-api.evervault.io
> cargo build 
> ln -s /<PATH-TO-CAGE-CLI-DIR>/cage-cli/target/debug/ev-cage /usr/local/bin/ev-cage 
> ev-cage cert new --subj "/CN=EV/C=IE/ST=LEI/L=DUB/O=Evervault/OU=Eng"
> ev-cage init --name <name> --signing-cert ./cert.pem --private-key ./key.pem -f <dockerfile_path> --api-key <API_KEY> # can also pass --enable-egress here
> ev-cage deploy --api-key <API_KEY>
```

When you deploy your cage it will be available at `<cageName>.<appUuid>.cages.evervault.dev`. The cert it will serve is untrusted so use `-k` with curl, or `NODE_TLS_REJECT_UNAUTHORIZED=0`

