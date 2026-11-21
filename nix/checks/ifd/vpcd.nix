{
  nodes.host.services.sftcrd = {
    mode = "vpcd";
    config = {
      serial = 54321;
      piv.slots."9a".key = "p256";
      pgp.slots.sign.key = "ed25519";
    };
  };

  testScript = ''
    import json

    reader_conf = host.succeed("cat /etc/reader.conf")
    assert "vpcd" in reader_conf, f"Expected vpcd in reader.conf:\n{reader_conf}"

    readers = host.succeed("opensc-tool -l")
    assert "Virtual PCD" in readers and "Yes" in readers, f"Expected Virtual PCD reader:\n{readers}"

    piv_info = json.loads(host.succeed("keyroostctl piv info --json"))
    assert piv_info["serial"] == "54321", f"Unexpected PIV serial: {piv_info}"

    pgp_info = json.loads(keyroostctl("openpgp info --json"))
    assert pgp_info["key_present_sig"] is True, f"Expected PGP sign key: {pgp_info}"
  '';
}
