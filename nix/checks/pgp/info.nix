{
  nodes.host.services.sftcrd.config = {
    serial = 43210;

    pgp = {
      user_pin = "654321";
      admin_pin = "87654321";
      name = "Doe<<Jane";
      url = "https://example.com/key.asc";

      slots = {
        sign.key = "ed25519";
        decrypt.key = ''
          -----BEGIN PRIVATE KEY-----
          MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYMU8CVjfJeB+70ru
          /NHmQO6CQSZFQmisQ79g//CB/4WhRANCAATHXXM5uR7Wo+zCW1bycqXoqy/9wRVQ
          v75NJ4SWaIbfBJB1wobcA3M3qcIhRgtE3dxX3MX9yxFBcF7JQ6X/bLfI
          -----END PRIVATE KEY-----
        '';
      };
    };
  };

  testScript = ''
    import json

    def info():
        return json.loads(keyroostctl("openpgp info --json"))

    output = info()
    assert output["serial"] == "0000A8CA", f"Invalid serial: {output['serial']=}"
    assert output["sig_algo"] == "EdDSA Ed25519", f"Invalid sig_algo: {output['sig_algo']=}"
    assert output["dec_algo"] == "ECDH NIST P-256", f"Invalid dec_algo: {output['dec_algo']=}"
    assert output["aut_algo"] == "RSA-2048", f"Invalid aut_algo: {output['aut_algo']=}"
    assert output["key_present_sig"] is True
    assert output["key_present_dec"] is True
    assert not output["key_present_aut"]
    assert output["fingerprint_sig"] is not None and len(output["fingerprint_sig"]) == 40
    assert output["fingerprint_dec"] is not None and len(output["fingerprint_dec"]) == 40
    assert output["fingerprint_aut"] is None
    assert output["user_pin_retries"] == 3
    assert output["admin_pin_retries"] == 3
    assert output["signature_count"] == 0

    sign_show = keyroostctl("openpgp key show --slot sign")
    assert "Ed25519" in sign_show or "point" in sign_show.lower() or len(sign_show.strip()) > 0

    decrypt_show = keyroostctl("openpgp key show --slot decrypt")
    assert len(decrypt_show.strip()) > 0

    # Custom PINs work, default PINs fail
    keyroostctl("openpgp pin verify --pin env:PIN", PIN="654321")
    keyroostctl("openpgp pin verify --admin --pin env:ADMIN_PIN", ADMIN_PIN="87654321")
    host.fail("PIN=123456 keyroostctl openpgp pin verify --pin env:PIN")
    host.fail("ADMIN_PIN=12345678 keyroostctl openpgp pin verify --admin --pin env:ADMIN_PIN")

    # Verify cardholder name and URL via gpg --card-status
    host.succeed("mkdir -p /root/.gnupg && chmod 700 /root/.gnupg && echo disable-ccid > /root/.gnupg/scdaemon.conf")
    card_status = host.succeed("gpg --card-status")
    assert "Jane Doe" in card_status, f"Missing cardholder name in:\n{card_status}"
    assert "https://example.com/key.asc" in card_status, f"Missing URL in:\n{card_status}"
  '';
}
