<a href="https://evervault.com/cages"><img src="https://evervault.com/images/logo-color.svg" height="45" /></a>

# Cages CLI

Command Line Tool to build, deploy and manage Evervault [Cages](https://github.com/evervault/cages/)

## Notice on Open Source Status of this project
The Evervault Cages product is open source with the aim of providing transparency to users — this is vital given that our process runs in the enclave, and is accounted for in the attestation.

The current state of this project does not allow for self-hosting. We plan on addressing this by abstracting away the Evervault-specific elements of the Cages product.

## Subcommands

### init

Initialize a Cage.toml in the current directory. Must provide a cage name.

`ev-cage init --name my-cage`

### build

Build a Cage from a Dockerfile. Defaults to use local `cage.toml` file for configuration. See more options with `-h`.

`ev-cage build`

### deploy

Deploy a Cage from a toml file. Builds a cage from a Dockerfile and then deploys the cage. You can provide a path to an EIF which was already build. See more options with `-h`.

`ev-cage deploy`

### delete

Delete a Cage from a toml file.

`ev-cage delete`

### attest

Validate the attestation doc provided by a Cage. Defaults to compare against the local `cage.toml` file.

### env

Manage Cage environment. Any changes to environment variables require a deployment to take effect.

#### add

Add a Cage environment variable. Add `--secret` to encrypt the value.

`ev-cage env add --key ENV_VAR_1 --value ENV_VAR`

#### get

Get Cage environment variables.

`ev-cage env get`

#### delete

Delete a Cage environment variable. 

`ev-cage env delete --key ENV_VAR_1`

### describe

Get the PCRs of a built EIF. Defaults to `./enclave.eif`

`ev-cage describe `

### list

List your Cages and Deployments.

#### cages

List Cages

`ev-cage list cages`

#### deployments

List Deployments of a specific cage. Defaults to the local `./cage.toml` file

`ev-cage list deployments`

### cert

Create a new Cage signing certificate

`ev-cage cert new`

### logs

Pull the logs for a Cage into. Defaults to the local `./cage.toml` file.

`ev-cage logs`

### encrypt

Encrypt a string with the CLI.

`ev-cage encrypt super-secret-value`

### update

Check for new versions of the CLI and install them.

`ev-cage update`

