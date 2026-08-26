<a href="https://docs.evervault.com/sdks/cli"><img src="https://evervault.com/images/logo-color.svg" height="45" /></a>

# Evervault CLI

The Evervault CLI helps you manage your Evervault resources from the terminal.

# Installation
Run the following command to install the Evervault CLI:
```
curl https://cli.evervault.com/v4/install -sL | sh
```

## Nix

This repo is a flake, so you can run the CLI without installing it:
```
nix run github:evervault/evervault-cli -- --help
```

To make `nix-shell -p evervault-cli` work, add the overlay to your own Nix config
(this is not in nixpkgs, so it has to be added per-machine):
```
mkdir -p ~/.config/nixpkgs/overlays
cat > ~/.config/nixpkgs/overlays/evervault-cli.nix <<'EOF'
final: prev: {
  evervault-cli = final.callPackage "${builtins.fetchTarball
    "https://github.com/evervault/evervault-cli/archive/refs/heads/main.tar.gz"}/nix/evervault-cli.nix" { };
}
EOF
```

Both build the CLI version pinned in [`nix/evervault-cli.nix`](nix/evervault-cli.nix);
bump `version` and `srcHash` there when a new version is released.

# [Documentation](https://docs.evervault.com/sdks/cli)
For a full reference see the [Documentation Site](https://docs.evervault.com/sdks/cli). Try running `ev --help` to see the available commands.

## Known Issues

The enclave commands are incompatible with Docker Engine >= 25.0.0. This is due to a change in the Docker Engine API v1.44 becoming incompatible with a dependency used within the Nitro CLI. We are working to rectify this issue. 

More information on this issue can be found [here](https://github.com/aws/aws-nitro-enclaves-cli/issues/537).
