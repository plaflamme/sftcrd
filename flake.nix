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
    flake-parts.lib.mkFlake { inherit inputs; } {

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      imports = [
        inputs.rust-flake.flakeModules.default
        inputs.rust-flake.flakeModules.nixpkgs
      ];

      perSystem =
        {
          config,
          system,
          pkgs,
          ...
        }:
        {
          rust-project = {
            crates = {
              sftcrd =
                { ... }:
                {
                  crane = {
                    extraBuildArgs = {
                      CARGO_PROFILE = "dev"; # TODO: how do we output both release and dev profiles?
                    };
                  };
                };
            };
          };

          packages = {
            default = config.packages.sftcrd;
          };

          checks =
            let
              sftcrd = config.packages.sftcrd;
            in
            { }
            // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
              piv-info = pkgs.callPackage ./nix/checks/piv-info.nix {
                inherit keyroost sftcrd system;
              };
              piv-pin-change = pkgs.callPackage ./nix/checks/piv-pin-change.nix {
                inherit keyroost sftcrd system;
              };
              piv-puk-change = pkgs.callPackage ./nix/checks/piv-puk-change.nix {
                inherit keyroost sftcrd system;
              };
              piv-pin-block = pkgs.callPackage ./nix/checks/piv-pin-block.nix {
                inherit keyroost sftcrd system;
              };
              piv-reset = pkgs.callPackage ./nix/checks/piv-reset.nix {
                inherit keyroost sftcrd system;
              };
              piv-algorithms = pkgs.callPackage ./nix/checks/piv-algorithms.nix {
                inherit keyroost sftcrd system;
              };
              piv-multi-slot = pkgs.callPackage ./nix/checks/piv-multi-slot.nix {
                inherit keyroost sftcrd system;
              };
              piv-attest = pkgs.callPackage ./nix/checks/piv-attest.nix {
                inherit keyroost sftcrd system;
              };
            };

          devShells.default = config.devShells.rust;
        };
    };
}
