# Cages CLI

Build, deploy and manage Cages

## Run Locally

```
> cargo build
> ln -s /<PATH-TO-CAGE-CLI-DIR>/cage-cli/target/debug/ev-cage /usr/local/bin/ev-cage
> ev-cage init --name <name> --generate-signing -f <dockerfile_path> --api-key <API_KEY> # can also pass --egress here
> ev-cage deploy --api-key <API_KEY>
```

When you deploy your cage it will be available at `<cageName>.<appUuid>.cages.evervault.com`. The cert it will serve is untrusted so use `-k` with curl, or `NODE_TLS_REJECT_UNAUTHORIZED=0`
