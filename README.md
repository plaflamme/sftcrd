# sftcrd

[![check](https://github.com/plaflamme/sftcrd/actions/workflows/check.yaml/badge.svg)](https://github.com/plaflamme/sftcrd/actions/workflows/check.yaml)
[![rustdoc](https://img.shields.io/badge/docs-rustdoc-blue)](https://plaflamme.github.io/sftcrd/rustdoc/index.html)

`sftcrd` (*soft card*) is a pure-Rust software implementation of a [Smart Card](https://en.wikipedia.org/wiki/Smart_card) designed to make testing software that relies on smart cards easier. It connects directly to `pcscd` via a custom PC/SC-Lite [IFD Handler](https://pcsclite.apdu.fr/api/group__IFDHandler.html#details) (`libsftcrd_ifd.so`) over a Unix domain socket, or via the [VSmartCard](https://github.com/frankmorgner/vsmartcard) (`vpcd`) TCP protocol, and can run either as a NixOS service or as a standalone binary.

> [!WARNING]
> This project makes no guarantees about the correctness of its cryptographic functionalities. Do not use this project for production or physical smart card deployments.

## Features

- **PIV Applet** (NIST SP 800-73-4 / FIPS 201 with Yubico extensions):
  - Standard slots (`9A`, `9C`, `9D`, `9E`) and 20 retired key-management slots (`82`–`95`)
  - `9B` management key (`3DES`, `AES-128`, `AES-192`, `AES-256`) and `F9` key attestation
  - Application PIN/PUK, CHUID, PIN-protected data, and Yubico extensions (`GetVersion`, `GetSerial`, `GetMetadata`, `ImportAsymmetricKey`, `MoveKey`, `SetManagementKey`, `SetPinRetries`, `Reset`, `Attest`)
- **OpenPGP Card v3.4 Applet**:
  - Signature (`sign`), decryption (`decrypt`), and authentication (`aut`) slots
  - `PW1` (user), `RC` (resetting code), and `PW3` (admin) PINs with retry counters
  - `PSO:CDS`, `PSO:DECIPHER`, `INTERNAL AUTHENTICATE`, key generation/import, cardholder metadata, and `TERMINATE DF` / `ACTIVATE FILE` factory reset
- **Supported Key Algorithms**:
  - RSA (`1024`, `2048`, `3072`, `4096`)
  - NIST ECC (`P-256`, `P-384`, `P-521`)
  - `Ed25519` and `X25519`
- **Multiple PC/SC Transports**:
  - **Direct `pcscd` (`pcscd`, default)**: Custom PC/SC-Lite IFD Handler v3 shared library (`libsftcrd_ifd.so`) communicating with `sftcrd pcscd` over a Unix domain socket (with systemd socket activation support and no `vsmartcard-vpcd` dependency)
  - **VSmartCard (`vpcd`)**: TCP listener (`sftcrd vpcd`) compatible with `vsmartcard-vpcd`
- **Declarative Initial State**: Pre-populate keys, certificates, PINs, serial number, and policies from a TOML file or NixOS configuration.

> [!NOTE]
> Card state is held **in memory for the lifetime of the `sftcrd` process** and persists across PC/SC and `vpcd` client reconnections. Restarting `sftcrd` re-initializes the card from the `--config` file (or factory defaults).

### Factory Defaults

When started without overrides in `--config`:

| Setting | Default |
| :--- | :--- |
| Serial number | `87654321` |
| ATR | `3BFD1300008131FE158073C021C057597562694B657940` (YubiKey 5.7) |
| PIV PIN / PUK | `123456` (5 tries) / `12345678` (3 tries) |
| PIV 9B Management Key | `010203040506070801020304050607080102030405060708` (3DES) |
| OpenPGP User PIN (`PW1`) | `123456` (3 tries) |
| OpenPGP Admin PIN (`PW3`) | `12345678` (3 tries) |
| OpenPGP Resetting Code (`RC`) | Unset (3 tries) |

## Getting Started

### NixOS Module

Enable `services.sftcrd` in your NixOS configuration. By default (`mode = "pcscd"`), the module configures `services.pcscd` with `libsftcrd_ifd.so` and a socket-activated `sftcrd.socket` / `sftcrd.service` — no `vsmartcard-vpcd` required:

```nix
{
  inputs = {
    sftcrd.url = "github:plaflamme/sftcrd";
  };
  outputs = { sftcrd, ... }: {
    nixosConfigurations.my-host = {
      imports = [
        sftcrd.nixosModules.sftcrd
      ];
      services.sftcrd = {
        enable = true;
        # mode = "pcscd"; # default (direct pcscd over Unix socket); or "vpcd" for VSmartCard TCP

        # Optionally configure the card's initial state
        config = {
          serial = 12345;

          piv.slots."9a" = {
            key = ''
              -----BEGIN PRIVATE KEY-----
              MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYMU8CVjfJeB+70ru
              /NHmQO6CQSZFQmisQ79g//CB/4WhRANCAATHXXM5uR7Wo+zCW1bycqXoqy/9wRVQ
              v75NJ4SWaIbfBJB1wobcA3M3qcIhRgtE3dxX3MX9yxFBcF7JQ6X/bLfI
              -----END PRIVATE KEY-----
            '';
          };

          pgp = {
            name = "Doe<<Jane";
            slots.sign.key = "ed25519";
          };
        };
      };
    };
  };
}
```

To use the VSmartCard TCP transport instead, set `services.sftcrd.mode = "vpcd";` (which enables `services.vsmartcard-vpcd` and configures `sftcrd vpcd`).

Refer to the [NixOS module options](https://plaflamme.github.io/sftcrd/options.html) and the [configuration reference](https://plaflamme.github.io/sftcrd/config.html) for all available settings.

Once `sftcrd` is running, interact with it through PC/SC:

```bash
$ nix shell nixpkgs#opensc --command opensc-tool -l
# Detected readers (pcsc)
Nr.  Card  Features  Name
0    Yes             sftcrd 00 00
```

```bash
$ nix shell nixpkgs#opensc --command opensc-tool -r "sftcrd 00 00" -a
3b:fd:13:00:00:81:31:fe:15:80:73:c0:21:c0:57:59:75:62:69:4b:65:79:40
```

```bash
$ nix shell nixpkgs#yubico-piv-tool --command yubico-piv-tool -r "sftcrd" -a status
Version:        5.7.4
Serial Number:  12345
CHUID:  No data available
CCC:    No data available
All non-listed slots are empty
PIN tries left: 5
```

```bash
$ gpg --card-status
```

### Standalone CLI

`sftcrd` exposes two transport subcommands:

- **`sftcrd pcscd`**: Listens on a Unix domain socket (or uses systemd socket activation via `LISTEN_PID` / `LISTEN_FDS`) for `libsftcrd_ifd.so` connections.
- **`sftcrd vpcd`**: Listens on a TCP socket for `vsmartcard-vpcd` (configured in connect mode).

Run directly with Nix or Cargo:

```bash
# Direct pcscd (Unix socket) mode:
nix run github:plaflamme/sftcrd -- pcscd --socket /run/sftcrd/sftcrd.sock --config ./card.toml

# VSmartCard (vpcd TCP) mode:
nix run github:plaflamme/sftcrd -- vpcd --host 127.0.0.1 --port 35963 --config ./card.toml

# Or inside the repo devShell:
cargo run -p sftcrd -- pcscd --socket /tmp/sftcrd.sock --config ./card.toml
```

Available CLI options:

- Global options:
  - `--atr <HEX>`: ATR presented to PC/SC clients as a hex string (default: YubiKey 5.7 ATR)
  - `-c, --config <PATH>`: Path to a TOML configuration file to initialize card state
  - `RUST_LOG`: Controls log verbosity via `tracing` (default: `info`, e.g. `RUST_LOG=trace` to inspect APDUs)
- `sftcrd pcscd`:
  - `--socket <PATH>`: Unix domain socket path to bind (default: `/run/sftcrd/sftcrd.sock`; ignored when systemd socket activation is active)
- `sftcrd vpcd`:
  - `--host <HOST>`: Host address to bind the TCP listener on (default: `127.0.0.1`)
  - `--port <PORT>`: TCP port to listen on for `vpcd` connections (default: `35963`)

## Development & Testing

Enter the Nix development shell (`nix develop`) or use `direnv`, then run Rust unit tests and lints:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
```

### NixOS VM Integration Checks

On `x86_64-linux`, the flake defines NixOS VM integration tests under `nix/checks/piv/`, `nix/checks/pgp/`, and `nix/checks/ifd/` exercising `sftcrd` end-to-end against `pcscd`, `libsftcrd_ifd.so`, `vpcd`, `opensc-tool`, `keyroostctl`, `yubico-piv-tool`, `gnupg`, and `openssl`:

```bash
# Run all checks (including VM tests on x86_64-linux)
nix flake check

# Run individual VM tests
nix build -L .#checks.x86_64-linux.vm-ifd-reconnect
nix build -L .#checks.x86_64-linux.vm-ifd-vpcd
nix build -L .#checks.x86_64-linux.vm-piv-info
nix build -L .#checks.x86_64-linux.vm-pgp-info
```

### Documentation

Build the static documentation site (powered by `ndg`, including generated NixOS module options and `sftcrd config-reference`) locally:

```bash
nix build -L .#docs
```
