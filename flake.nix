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
    keyroost.url = "github:framefilter/keyroost/v0.15.0";
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
          }:
          let
            keyroostctl = keyroost.packages.${system}.keyroostctl;
          in
          {

            packages =
              let
                craneLib = config.rust-project.crane-lib;
                src = config.rust-project.src;
              in
              {
                default = config.packages.sftcrd;
                sftcrd-debug = craneLib.buildPackage (
                  config.rust-project.crates.sftcrd.crane.args
                  // {
                    inherit src;
                    pname = "sftcrd-debug";
                    CARGO_PROFILE = "dev";
                  }
                );
              };

            checks =
              { }
              // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
                piv-info = pkgs.callPackage ./nix/checks/piv-info.nix {
                  inherit keyroostctl nixosModule;
                };
                piv-pin-change = pkgs.callPackage ./nix/checks/piv-pin-change.nix {
                  inherit keyroostctl nixosModule;
                };
                piv-puk-change = pkgs.callPackage ./nix/checks/piv-puk-change.nix {
                  inherit keyroostctl nixosModule;
                };
                piv-pin-block = pkgs.callPackage ./nix/checks/piv-pin-block.nix {
                  inherit keyroostctl nixosModule;
                };
                piv-reset = pkgs.callPackage ./nix/checks/piv-reset.nix {
                  inherit keyroostctl nixosModule;
                };
                piv-algorithms = pkgs.callPackage ./nix/checks/piv-algorithms.nix {
                  inherit keyroostctl nixosModule;
                };
                piv-multi-slot = pkgs.callPackage ./nix/checks/piv-multi-slot.nix {
                  inherit keyroostctl nixosModule;
                };
                piv-attest = pkgs.callPackage ./nix/checks/piv-attest.nix {
                  inherit keyroostctl nixosModule;
                };
              };

            devShells.default = config.devShells.rust;
          };
      }
    );
}
