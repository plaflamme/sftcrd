# sftcrd

`sftcrd` is a software implementation of a [Smart Card](https://en.wikipedia.org/wiki/Smart_card) designed to make testing other software that use them easier.

> [!WARNING]
> This project makes not guarantees about the correctness of the cryptographic functionalities. Do not use this project for actual production/physical smart card implementations.

## Features

* PIV Applet (NIST SP 800-73-5) implementation with Yubico extensions

## Getting Started

Use the nixos module:

```nix
{
  inputs = {
    sftcrd.url = "github:plaflamme/sftcrd";
  };
  outputs = { sftcrd, ... }: {
    nixosConfigurations.my-host = {
      imports = [
        sftcrd.nixosModules.default
      ];
      services.sftcrd.enable = true;
    };
  };
}
```

Refer to the [module's options](options.html) to see how to configure the module.

Once the `sftcrd` service is running, you should be able to interact with it through PC/SC and `vpcd` ([vsmartcard](https://github.com/frankmorgner/vsmartcard) daemon):

```bash
$ nix shell nixpkgs#opensc --command opensc-tool -l
# Detected readers (pcsc)
Nr.  Card  Features  Name
0    Yes             Virtual PCD 00 00
1    No              Virtual PCD 00 01
```

```bash
$ nix shell nixpkgs#opensc --command opensc-tool -r "Virtual PCD 00 00" -a
3b:fd:13:00:00:81:31:fe:15:80:73:c0:21:c0:57:59:75:62:69:4b:65:79:40
```

```bash
$ nix shell nixpkgs#yubico-piv-tool -r "Virtual PCD 00 00" -a status
Version:        5.7.4
Serial Number:  16909060
CHUID:  No data available
CCC:    No data available
All non-listed slots are empty
PIN tries left: 5
```
