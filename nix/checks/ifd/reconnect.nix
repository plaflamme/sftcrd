{
  nodes.host.services.sftcrd = {
    mode = "pcscd";
    config = {
      serial = 43210;
      piv.slots."9a".key = "p256";
      pgp = {
        name = "Doe<<Jane";
        slots.sign.key = "ed25519";
      };
    };
  };

  testScript = ''
    import json

    # Verify vsmartcard-vpcd is not configured and libsftcrd_ifd.so is registered.
    reader_conf = host.succeed("cat /etc/reader.conf")
    assert "libsftcrd_ifd.so" in reader_conf, f"Expected libsftcrd_ifd.so in reader.conf:\n{reader_conf}"
    assert "vpcd" not in reader_conf, f"Unexpected vpcd entry in reader.conf:\n{reader_conf}"

    # Verify reader detection and ATR via opensc-tool.
    readers = host.succeed("opensc-tool -l")
    assert "sftcrd" in readers and "Yes" in readers, f"Expected sftcrd reader with card present:\n{readers}"
    atr = host.succeed("opensc-tool -a").strip().lower()
    assert atr.startswith("3b:fd:13:00:00:81:31"), f"Unexpected ATR: {atr}"

    # Verify PIV via keyroostctl and yubico-piv-tool.
    piv_info = json.loads(host.succeed("keyroostctl piv info --json"))
    assert piv_info["serial"] == "43210", f"Unexpected serial: {piv_info}"

    yubico_status = host.succeed("yubico-piv-tool -r sftcrd -a status")
    assert "43210" in yubico_status, f"Expected serial in yubico-piv-tool status:\n{yubico_status}"

    # Verify OpenPGP via keyroostctl and gpg.
    pgp_info = json.loads(keyroostctl("openpgp info --json"))
    assert pgp_info["serial"] == "0000A8CA", f"Unexpected PGP serial: {pgp_info}"

    host.succeed("mkdir -p /root/.gnupg && chmod 700 /root/.gnupg && echo disable-ccid > /root/.gnupg/scdaemon.conf")
    card_status = host.succeed("gpg --card-status")
    assert "Jane Doe" in card_status, f"Missing cardholder name in:\n{card_status}"

    # Stop sftcrd.socket + sftcrd.service and verify pcscd observes card absence.
    host.succeed("systemctl stop sftcrd.socket sftcrd.service")
    host.wait_until_succeeds("opensc-tool -l | grep -qE 'No[[:space:]]+.*sftcrd'")

    # Start sftcrd.socket + sftcrd.service again and verify card reappears and works.
    host.succeed("systemctl start sftcrd.socket sftcrd.service")
    host.wait_for_unit("sftcrd.service")
    host.wait_until_succeeds("opensc-tool -l | grep -qE 'Yes[[:space:]]+.*sftcrd'")

    piv_after_start = json.loads(host.succeed("keyroostctl piv info --json"))
    assert piv_after_start["serial"] == "43210", f"Unexpected serial after start: {piv_after_start}"

    # Restart sftcrd.service in place (with sftcrd.socket active) and verify clean reconnect.
    host.succeed("systemctl restart sftcrd.service")
    host.wait_for_unit("sftcrd.service")
    host.wait_until_succeeds("keyroostctl piv info --json | grep -q '\"43210\"'")
  '';
}
