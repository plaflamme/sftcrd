{
  testScript = ''
    import json

    def info():
        return json.loads(keyroostctl("openpgp info --json"))

    # Generate a new OpenPGP key set with backup and put all three keys on the card
    keyroostctl(
        "openpgp key import --generate --backup /tmp/backup --name 'Test User' --email 'test@example.com' --passphrase env:PASS --admin-pin env:ADMIN_PIN --yes",
        PASS="secretpass",
    )

    state = info()
    assert state["key_present_sig"] is True
    assert state["key_present_dec"] is True
    assert state["key_present_aut"] is True
    fps = (state["fingerprint_sig"], state["fingerprint_dec"], state["fingerprint_aut"])
    assert all(fp is not None and len(fp) == 40 for fp in fps)

    # Sign a test message with the imported signing key
    host.succeed("printf 'hello openpgp' > /tmp/msg.txt")
    sig = keyroostctl("openpgp sign --in /tmp/msg.txt --pin env:PIN")
    assert len(sig.strip()) > 0

    # Check gpg --card-status interop
    host.succeed("mkdir -p /root/.gnupg && chmod 700 /root/.gnupg && echo disable-ccid > /root/.gnupg/scdaemon.conf")
    card_status = host.succeed("gpg --card-status")
    host.succeed("gpgconf --kill scdaemon")
    normalized = card_status.replace(" ", "")
    for fp in fps:
        assert fp.upper() in normalized, f"Fingerprint {fp} not found in gpg --card-status:\n{card_status}"

    # Reset the card and restore from backup
    keyroostctl("openpgp reset --yes")
    reset_state = info()
    assert not reset_state["key_present_sig"]
    assert not reset_state["key_present_dec"]
    assert not reset_state["key_present_aut"]

    keyroostctl(
        "openpgp key import --in /tmp/backup.asc --passphrase env:PASS --admin-pin env:ADMIN_PIN --yes",
        PASS="secretpass",
    )
    restored = info()
    assert (restored["fingerprint_sig"], restored["fingerprint_dec"], restored["fingerprint_aut"]) == fps

    # Import an RSA-2048 PEM private key into the sign slot
    host.succeed("openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /tmp/rsa.pem")
    keyroostctl("openpgp key import --in /tmp/rsa.pem --slot sign --admin-pin env:ADMIN_PIN --yes")
    rsa_state = info()
    assert rsa_state["sig_algo"] == "RSA-2048"
    assert rsa_state["key_present_sig"] is True
    assert rsa_state["fingerprint_sig"] != fps[0]
    rsa_sig = keyroostctl("openpgp sign --in /tmp/msg.txt --pin env:PIN")
    assert len(rsa_sig.strip()) > 0
  '';
}
