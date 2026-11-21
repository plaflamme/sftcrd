withSystem:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.sftcrd;
in
{
  options.services.sftcrd = {
    enable = lib.mkEnableOption "A configurable software-based smart card";

    mode = lib.mkOption {
      type = lib.types.enum [
        "ifd"
        "vpcd"
      ];
      default = "ifd";
      description = ''
        Transport mode used to connect `sftcrd` to `pcscd`.

        - `"ifd"`: Direct PC/SC connection via `libsftcrd_ifd.so` over a Unix domain
          socket (does not require `vsmartcard-vpcd`).
        - `"vpcd"`: TCP connection via `services.vsmartcard-vpcd`.
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = withSystem pkgs.stdenv.hostPlatform.system (
        sysContext: sysContext.config.packages.sftcrd
      );
      defaultText = lib.literalMD "packages.sftcrd from this flake";
      description = ''
        The package used by the sftcrd systemd service.
      '';
    };

    ifdPackage = lib.mkOption {
      type = lib.types.package;
      default = withSystem pkgs.stdenv.hostPlatform.system (
        sysContext: sysContext.config.packages.sftcrd-ifd
      );
      defaultText = lib.literalMD "packages.sftcrd-ifd from this flake";
      description = ''
        The `sftcrd-ifd` PC/SC-Lite IFD handler package loaded by `pcscd` when
        `mode = "ifd"`.
      '';
    };

    socket = lib.mkOption {
      type = lib.types.str;
      default = "/run/sftcrd/sftcrd.sock";
      description = ''
        Unix domain socket path used by `sftcrd pcsc` and `libsftcrd_ifd.so` when
        `mode = "ifd"`.
      '';
    };

    atr = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "3BFD1300008131FE158073C021C057597562694B657940";
      description = ''
        ATR presented to PC/SC clients, as a hex string.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 35963;
      description = ''
        Port number sftcrd will listen on for connections from vpcd when
        `mode = "vpcd"`.
      '';
    };

    hostname = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = ''
        Hostname or IP address sftcrd will listen on for connections from vpcd
        when `mode = "vpcd"`.
      '';
    };

    log-level = lib.mkOption {
      default = "info";
      type = lib.types.enum [
        "trace"
        "debug"
        "info"
        "warn"
        "error"
      ];
      description = "Set the log level";
    };

    config = lib.mkOption {
      type = lib.types.nullOr lib.types.toml;
      default = null;
      description = ''
        TOML configuration to initialize the card state.
      '';
      example = lib.literalExpression ''
        {
          serial = 12345;

          piv.slots = {
            "9a".key = "p256";
            "9c" = {
              key = '''
                -----BEGIN PRIVATE KEY-----
                MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYMU8CVjfJeB+70ru
                /NHmQO6CQSZFQmisQ79g//CB/4WhRANCAATHXXM5uR7Wo+zCW1bycqXoqy/9wRVQ
                v75NJ4SWaIbfBJB1wobcA3M3qcIhRgtE3dxX3MX9yxFBcF7JQ6X/bLfI
                -----END PRIVATE KEY-----
              ''';
              pin_policy = "never";
            };
          };
        };
      '';
    };
  };

  config =
    let
      configToml =
        if (cfg.config != null) then (pkgs.formats.toml { }).generate "sftcrd.toml" cfg.config else null;
      commonArgs =
        lib.optionalString (cfg.atr != null) " --atr ${cfg.atr}"
        + lib.optionalString (configToml != null) " --config ${configToml}";
    in
    lib.mkIf cfg.enable (
      lib.mkMerge [
        {
          services.pcscd.enable = true;

          systemd.services.sftcrd = {
            wantedBy = [ "multi-user.target" ];
            serviceConfig = {
              Environment = "RUST_LOG=${cfg.log-level}";
            };
          };
        }

        (lib.mkIf (cfg.mode == "ifd") {
          services.pcscd.readerConfigs = [
            ''
              FRIENDLYNAME      "sftcrd"
              DEVICENAME        ${cfg.socket}
              LIBPATH           ${cfg.ifdPackage}/lib/libsftcrd_ifd.so
              CHANNELID         1
            ''
          ];

          systemd.sockets.sftcrd = {
            description = "sftcrd PC/SC IFD Unix domain socket";
            wantedBy = [ "sockets.target" ];
            before = [ "pcscd.service" ];
            socketConfig = {
              ListenStream = cfg.socket;
              SocketGroup = "pcscd";
              SocketMode = "0660";
              DirectoryMode = "0755";
            };
          };

          systemd.services.sftcrd = {
            requires = [ "sftcrd.socket" ];
            after = [ "sftcrd.socket" ];
            serviceConfig.ExecStart = "${cfg.package}/bin/sftcrd pcsc --socket ${cfg.socket}${commonArgs}";
          };

          systemd.services.pcscd = {
            after = [ "sftcrd.socket" ];
            wants = [ "sftcrd.socket" ];
            serviceConfig.ReadWritePaths = [ "-${builtins.dirOf cfg.socket}" ];
          };
        })

        (lib.mkIf (cfg.mode == "vpcd") {
          services.vsmartcard-vpcd = {
            enable = true;
            port = cfg.port;
            hostname = cfg.hostname;
          };

          systemd.services.sftcrd.serviceConfig.ExecStart =
            "${cfg.package}/bin/sftcrd vpcd --port ${toString cfg.port} --host ${cfg.hostname}${commonArgs}";
        })
      ]
    );
}
