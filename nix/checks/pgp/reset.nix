{
  testScript = ''
    import json

    def info():
        return json.loads(keyroostctl("openpgp info --json"))

    new_pin = "654321"
    new_admin_pin = "87654321"

    # Change user and admin PINs
    keyroostctl("openpgp pin change --pin env:OLD --new-pin env:NEW", OLD="123456", NEW=new_pin)
    keyroostctl("openpgp pin change --admin --pin env:OLD --new-pin env:NEW", OLD="12345678", NEW=new_admin_pin)

    # Generate a key using the new admin PIN
    keyroostctl(
        "openpgp key generate --slot sign --algorithm ed25519 --admin-pin env:ADMIN_PIN --yes",
        ADMIN_PIN=new_admin_pin,
    )

    state = info()
    assert state["key_present_sig"] is True
    assert state["sig_algo"] == "EdDSA Ed25519"
    keyroostctl("openpgp pin verify --pin env:PIN", PIN=new_pin)

    # Factory reset
    keyroostctl("openpgp reset --yes")

    # Factory state restored: keys wiped, default algorithm & PINs work again
    state = info()
    assert not state["key_present_sig"]
    assert state["sig_algo"] == "RSA-2048"
    assert state["user_pin_retries"] == 3
    assert state["admin_pin_retries"] == 3
    keyroostctl("openpgp pin verify --pin env:PIN")
    keyroostctl("openpgp pin verify --admin --pin env:ADMIN_PIN")
    host.fail(f"PIN={new_pin} keyroostctl openpgp pin verify --pin env:PIN")
    host.fail(f"ADMIN_PIN={new_admin_pin} keyroostctl openpgp pin verify --admin --pin env:ADMIN_PIN")
  '';
}
