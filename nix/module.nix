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
        Port number sftcrd will be listening on for connections from vpcd.
      '';
    };

    hostname = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = ''
        Port number sftcrd will be listening on for connections from vpcd.
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
  };

  config = lib.mkIf cfg.enable {

    services.pcscd.enable = true;
    services.vsmartcard-vpcd = {
      enable = true;
      port = cfg.port;
      hostname = cfg.hostname;
    };

    systemd.services.sftcrd = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Environment = "RUST_LOG=${cfg.log-level}";
        ExecStart =
          "${cfg.package}/bin/sftcrd --port ${toString cfg.port} --host ${cfg.hostname}"
          + lib.optionalString (cfg.atr != null) " --atr ${cfg.atr}";
      };
    };
  };
}
