{
  nixConfig = {
    extra-substituters = [ "https://sftcrd.cachix.org" ];
    extra-trusted-public-keys = [
      "sftcrd.cachix.org-1:78q7W+VdLfgWcJqL8VxpjzzRxnacO9HA68mgwR880sE="
    ];
  };
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-flake = {
      url = "github:juspay/rust-flake";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
    };
    keyroost.url = "github:framefilter/keyroost/v0.16.0";
  };

  outputs =
    inputs@{ flake-parts, keyroost, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } (
      { withSystem, ... }:
      let
        nixosModule = import ./nix/module.nix withSystem;
      in
      {

        systems = [
          "x86_64-linux"
          "aarch64-linux"
          "aarch64-darwin"
        ];

        imports = [
          inputs.rust-flake.flakeModules.default
          inputs.rust-flake.flakeModules.nixpkgs
        ];

        flake = {
          nixosModules.sftcrd = nixosModule;
        };

        perSystem =
          {
            config,
            system,
            pkgs,
            ...
          }@inputs:
          let
            keyroostctl = keyroost.packages.${system}.keyroostctl;
            eval = pkgs.lib.evalModules {
              modules = [
                nixosModule
                { _module.check = false; }
              ];
            };
            optionsDoc = pkgs.nixosOptionsDoc { options = eval.options; };
            craneLib = config.rust-project.crane-lib;
            src = config.rust-project.src;
            sftcrd = config.packages.sftcrd;
            workspaceArgs = config.rust-project.crates.sftcrd.crane.args // {
              inherit src;
              pname = "sftcrd-workspace";
              cargoExtraArgs = "--workspace";
            };
            workspaceArtifacts = craneLib.buildDepsOnly workspaceArgs;
            rustdoc = craneLib.cargoDoc (
              workspaceArgs
              // {
                pname = "sftcrd-rustdoc";
                cargoArtifacts = workspaceArtifacts;
                cargoDocExtraArgs = "--no-deps";
                RUSTDOCFLAGS = "-Z unstable-options --enable-index-page";
              }
            );
          in
          {

            packages = {
              default = sftcrd;
              inherit rustdoc;
              sftcrd-debug = craneLib.buildPackage (
                config.rust-project.crates.sftcrd.crane.args
                // {
                  inherit src;
                  pname = "sftcrd-debug";
                  CARGO_PROFILE = "dev";
                }
              );

              docs = pkgs.callPackage ./nix/docs.nix {
                inherit optionsDoc sftcrd rustdoc;
              };
            };

            checks =
              let
                ctx = inputs // {
                  inherit nixosModule keyroostctl;
                };
                sftcrd-workspace-test = craneLib.cargoTest (
                  workspaceArgs
                  // {
                    cargoArtifacts = workspaceArtifacts;
                  }
                );
              in
              (import ./nix/checks ctx)
              // {
                inherit rustdoc sftcrd-workspace-test;
              };

            devShells.default = config.devShells.rust;
          };
      }
    );
}
