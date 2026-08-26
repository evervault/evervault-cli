{ lib
, rustPlatform
, fetchFromGitHub
, pkg-config
, openssl
}:

let
  # Bump these together when a new CLI version is released.
  version = "4.5.1";
  srcHash = "sha256-I78wDnKxgj1rUPsBtl2tGKkLeSBTKgewhWAvFhivRDo=";

  src = fetchFromGitHub {
    owner = "evervault";
    repo = "evervault-cli";
    tag = "v${version}";
    hash = srcHash;
  };
in
rustPlatform.buildRustPackage {
  pname = "evervault-cli";
  inherit version src;

  cargoLock.lockFile = "${src}/Cargo.lock";

  # Mirrors crates/ev-cli/scripts/insert-cli-version.sh, which the release
  # workflow runs so `ev --version` reports the released version.
  postPatch = ''
    substituteInPlace crates/ev-cli/Cargo.toml \
      --replace-fail '1.0.0-dev' '${version}'
  '';

  cargoBuildFlags = [ "--package" "ev-cli" ];

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ openssl ];

  # ev-cli enables openssl's `vendored` feature; build against nixpkgs' openssl instead.
  env.OPENSSL_NO_VENDOR = "1";

  # The test suite talks to the Evervault API.
  doCheck = false;

  meta = {
    description = "Evervault CLI";
    homepage = "https://github.com/evervault/evervault-cli";
    license = lib.licenses.asl20;
    mainProgram = "ev";
  };
}
