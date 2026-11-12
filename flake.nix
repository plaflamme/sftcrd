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
            eval = pkgs.lib.evalModules {
              modules = [
                nixosModule
                { _module.check = false; }
              ];
            };
            optionsDoc = pkgs.nixosOptionsDoc { options = eval.options; };
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

                docs = pkgs.callPackage ./nix/docs.nix { inherit optionsDoc; };
              };

            checks =
              { }
              // pkgs.lib.optionalAttrs (system == "x86_64-linux") (
                builtins.listToAttrs (
                  map
                    (test: {
                      name = "${test}";
                      value = pkgs.testers.runNixOSTest {
                        name = "${test}";
                        imports = [
                          ./nix/checks/${test}.nix
                        ];
                        sshBackdoor.enable = true;
                        node = {
                          pkgsReadOnly = false;
                        };
                        defaults = {
                          imports = [ nixosModule ];
                          nixpkgs.overlays = [
                            (final: prev: {
                              inherit final;
                              keyroostctl = keyroostctl;
                            })
                          ];
                        };
                      };
                    })
                    [
                      "piv-algorithms"
                      "piv-info"
                      "piv-attest"
                      "piv-multi-slot"
                      "piv-pin-block"
                      "piv-pin-change"
                      "piv-puk-change"
                      "piv-reset"
                    ]
                )
              );

            devShells.default = config.devShells.rust;
          };
      }
    );
}
