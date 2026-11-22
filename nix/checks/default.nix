{
  pkgs,
  nixosModule,
  keyroostctl,
  system,
  ...
}:
let
  mkChecks =
    suite: extraPackages:
    builtins.listToAttrs (
      map
        (test: {
          name = "e2e-${suite}-${test}";
          value = pkgs.testers.runNixOSTest {

            name = "${suite}-${test}";

            imports = [
              ./${suite}/${test}.nix
            ];

            sshBackdoor.enable = true;

            nodes = {
              host =
                { pkgs, ... }:
                {
                  imports = [ nixosModule ];

                  services.sftcrd = {
                    enable = true;
                    log-level = "trace";
                  };

                  environment.systemPackages = [
                    pkgs.openssl
                    keyroostctl
                  ]
                  ++ extraPackages;
                };
            };

            testScript = pkgs.lib.mkBefore ''
              start_all()
              host.wait_for_unit("pcscd.socket")
              host.wait_for_unit("sftcrd.service")

              def keyroostctl(
                  args,
                  pin="123456",
                  mgmt="010203040506070801020304050607080102030405060708",
                  admin_pin="12345678",
                  **kwargs,
              ):
                  env_parts = []
                  if pin:
                      env_parts.append(f"PIN={pin}")
                  if mgmt:
                      env_parts.append(f"MGMT={mgmt}")
                  if admin_pin:
                      env_parts.append(f"ADMIN_PIN={admin_pin}")
                  for key, value in kwargs.items():
                      env_parts.append(f"{key}={value}")
                  env_str = " ".join(env_parts) + " " if env_parts else ""
                  cmd = f"{env_str}keyroostctl {args}"
                  return host.succeed(cmd)
            '';
          };
        })
        (
          map (name: pkgs.lib.strings.removeSuffix ".nix" name) (
            builtins.attrNames (builtins.readDir ./${suite})
          )
        )
    );
in
pkgs.lib.optionalAttrs (system == "x86_64-linux") (
  mkChecks "piv" [ pkgs.yubico-piv-tool ]
  // mkChecks "pgp" [ pkgs.gnupg ]
  // mkChecks "ifd" [
    pkgs.opensc
    pkgs.yubico-piv-tool
    pkgs.gnupg
  ]
)
