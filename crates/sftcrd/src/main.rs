//! Software smartcard daemon presenting PIV and `OpenPGP` applets over
//! either a direct PC/SC IFD Unix domain socket (`sftcrd pcscd`) or the
//! `VSmartCard` TCP protocol (`sftcrd vpcd`).

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use figment::Figment;
use figment::providers::{Format, Toml};
use toml_example::TomlExample;
use tracing_subscriber::EnvFilter;

use sftcrd::{CardConfig, DEFAULT_SERIAL, PgpApplet, PivApplet, pcscd, vpcd};

/// The ATR of a `YubiKey` 5.7
const DEFAULT_ATR: &str = "3BFD1300008131FE158073C021C057597562694B657940";

#[derive(Parser, Debug, Clone)]
#[command(
    name = "sftcrd",
    version,
    about = "Software smartcard daemon presenting PIV and OpenPGP applets"
)]
struct Args {
    /// ATR presented to PC/SC clients, as a hex string.
    #[arg(long, global = true, default_value = DEFAULT_ATR)]
    atr: String,

    /// Path to a TOML configuration file to initialize the card state.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Listen on a TCP socket for `VSmartCard` (`vpcd`) connections.
    Vpcd {
        /// Host to bind the listener on.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Port to listen on.
        #[arg(long, default_value_t = 35963u16)]
        port: u16,
    },

    /// Listen on a Unix domain socket for direct `pcscd` IFD handler connections.
    Pcscd {
        /// Unix domain socket path to bind (ignored when systemd socket activation is used).
        #[arg(long, default_value = pcscd::DEFAULT_SOCKET_PATH)]
        socket: PathBuf,
    },

    /// Print the reference TOML configuration wrapped in a Markdown code block.
    #[command(hide = true)]
    ConfigReference,
}

fn main() -> ExitCode {
    let args = Args::parse();

    if matches!(args.command, Command::ConfigReference) {
        println!("```toml");
        println!("{}", CardConfig::toml_example());
        println!("```");
        return ExitCode::SUCCESS;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let atr = match hex::decode(&args.atr) {
        Ok(atr) => atr,
        Err(e) => {
            tracing::error!("invalid --atr: {e}");
            return ExitCode::FAILURE;
        }
    };

    let (mut piv_applet, mut pgp_applet) = match init_applets(args.config.as_deref()) {
        Ok(applets) => applets,
        Err(e) => {
            tracing::error!("cannot initialize card state: {e}");
            return ExitCode::FAILURE;
        }
    };

    match args.command {
        Command::Vpcd { host, port } => {
            vpcd::run(&host, port, &atr, &mut piv_applet, &mut pgp_applet)
        }
        Command::Pcscd { socket } => pcscd::run(&socket, &atr, &mut piv_applet, &mut pgp_applet),
        Command::ConfigReference => unreachable!("handled above"),
    }
}

/// Initialize the PIV and `OpenPGP` applets from an optional TOML config file.
fn init_applets(config_path: Option<&Path>) -> io::Result<(PivApplet, PgpApplet)> {
    match config_path {
        Some(path) => {
            let card_config: CardConfig = Figment::new()
                .merge(Toml::file(path))
                .extract()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let serial = card_config.serial.unwrap_or(DEFAULT_SERIAL);
            let piv = PivApplet::from_config(&card_config.piv.unwrap_or_default(), serial)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let pgp = PgpApplet::from_config(&card_config.pgp.unwrap_or_default(), serial)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok((piv, pgp))
        }
        None => Ok((PivApplet::new(), PgpApplet::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_vpcd_and_pcscd_subcommands() {
        let vpcd = Args::try_parse_from([
            "sftcrd",
            "vpcd",
            "--host",
            "0.0.0.0",
            "--port",
            "12345",
            "--atr",
            "3B00",
        ])
        .expect("parse vpcd");
        assert_eq!(vpcd.atr, "3B00");
        assert!(matches!(
            vpcd.command,
            Command::Vpcd { ref host, port: 12345 } if host == "0.0.0.0"
        ));

        let pcscd = Args::try_parse_from([
            "sftcrd",
            "--config",
            "/etc/sftcrd.toml",
            "pcscd",
            "--socket",
            "/tmp/test.sock",
        ])
        .expect("parse pcscd");
        assert_eq!(pcscd.config, Some(PathBuf::from("/etc/sftcrd.toml")));
        assert!(matches!(
            pcscd.command,
            Command::Pcscd { ref socket } if socket == Path::new("/tmp/test.sock")
        ));

        let cfg_ref = Args::try_parse_from(["sftcrd", "config-reference"])
            .expect("parse config-reference");
        assert!(matches!(cfg_ref.command, Command::ConfigReference));
    }
}
