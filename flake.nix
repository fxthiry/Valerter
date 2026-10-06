# Development shell for valerter. With direnv, entering the directory loads it
# (see .envrc); without direnv, run `nix develop`.
#
# The Rust toolchain comes from nixpkgs (rust-toolchain.toml is only read by rustup,
# which CI uses). Release builds (musl static binary, .deb) are produced by CI.
{
  description = "valerter - development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/9fbb54b33e91ee4ca368e35a78e0613c720600b3";

  outputs =
    { nixpkgs, ... }:
    let
      eachSystem =
        f:
        nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (
          system: f nixpkgs.legacyPackages.${system}
        );
    in
    {
      devShells = eachSystem (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            # Native build dependencies of aws-lc-sys (rustls crypto backend).
            cmake
            perl
            gnumake
            # Packaging and coverage, as in CI.
            cargo-deb
            cargo-tarpaulin
          ];

          env.RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };
      });
    };
}
