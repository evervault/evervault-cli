<a href="https://evervault.com/primitives/enclaves"><img src="https://evervault.com/images/logo-color.svg" height="45" /></a>

# Enclave CLI

Command Line Tool to build, deploy and manage Evervault [Enclaves](https://github.com/evervault/enclaves/)

## Notice on Open Source Status of this project
The Evervault Enclaves product is open source with the aim of providing transparency to users — this is vital given that our process runs in the enclave, and is accounted for in the attestation.

The current state of this project does not allow for self-hosting. We plan on addressing this by abstracting away the Evervault-specific elements of the Enclaves product.

Learn more in the [docs](https://docs.evervault.com/primitives/enclaves)

## Known Issues

The Enclaves CLI is incompatible with Docker Engine >= 25.0.0. This is due to a change in the Docker Engine API v1.44 becoming incompatible with a dependency used within the Nitro CLI. We are working to rectify this issue. 

More information on this issue can be found [here](https://github.com/aws/aws-nitro-enclaves-cli/issues/537).
