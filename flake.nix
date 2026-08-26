{
  description = "Evervault CLI";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      overlays.default = import ./nix/overlay.nix;

      packages = forAllSystems (pkgs: rec {
        evervault-cli = pkgs.callPackage ./nix/evervault-cli.nix { };
        default = evervault-cli;
      });
    };
}
