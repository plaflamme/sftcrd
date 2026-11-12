{
  nodes = {
    host =
      { pkgs, ... }:
      {
        services.sftcrd = {
          enable = true;
          log-level = "trace";
        };

        environment.systemPackages = [
          pkgs.openssl
          pkgs.yubico-piv-tool
          pkgs.keyroostctl
        ];

      };
  };

  testScript = ''
    start_all()
    host.wait_for_unit("pcscd.socket")
    host.wait_for_unit("sftcrd.service")

    def keyroostctl(args, pin="123456", mgmt="010203040506070801020304050607080102030405060708", **kwargs):
        env_parts = []
        if pin:
            env_parts.append(f"PIN={pin}")
        if mgmt:
            env_parts.append(f"MGMT={mgmt}")
        for key, value in kwargs.items():
            env_parts.append(f"{key}={value}")
        env_str = " ".join(env_parts) + " " if env_parts else ""
        cmd = f"{env_str}keyroostctl {args}"
        return host.succeed(cmd)
  '';
}
