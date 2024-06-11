<a href="https://docs.evervault.com/sdks/cli"><img src="https://evervault.com/images/logo-color.svg" height="45" /></a>

# Evervault CLI

The Evervault CLI helps you manage your Evervault resources from the terminal.

# [Documentation](https://docs.evervault.com/sdks/cli)
See the documentation for a full reference on how to use the Evervault CLI. Try running `ev --help` to see the available commands.

## Known Issues

The enclave commands are incompatible with Docker Engine >= 25.0.0. This is due to a change in the Docker Engine API v1.44 becoming incompatible with a dependency used within the Nitro CLI. We are working to rectify this issue. 

More information on this issue can be found [here](https://github.com/aws/aws-nitro-enclaves-cli/issues/537).
