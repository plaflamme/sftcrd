{
  testScript = ''
    import json

    def info():
        return json.loads(keyroostctl("openpgp info --json"))

    # Verify default PINs
    keyroostctl("openpgp pin verify --pin env:PIN")
    keyroostctl("openpgp pin verify --admin --pin env:ADMIN_PIN")

    # Change user PIN and change back
    keyroostctl("openpgp pin change --pin env:OLD --new-pin env:NEW", OLD="123456", NEW="654321")
    keyroostctl("openpgp pin verify --pin env:PIN", PIN="654321")
    keyroostctl("openpgp pin change --pin env:OLD --new-pin env:NEW", OLD="654321", NEW="123456")

    # Change admin PIN and change back
    keyroostctl("openpgp pin change --admin --pin env:OLD --new-pin env:NEW", OLD="12345678", NEW="87654321")
    keyroostctl("openpgp pin verify --admin --pin env:ADMIN_PIN", ADMIN_PIN="87654321")
    keyroostctl("openpgp pin change --admin --pin env:OLD --new-pin env:NEW", OLD="87654321", NEW="12345678")

    # Decrement PW1 retry counter and block PW1
    assert info()["user_pin_retries"] == 3
    host.fail("BAD=000000 keyroostctl openpgp pin verify --pin env:BAD")
    assert info()["user_pin_retries"] == 2
    host.fail("BAD=000000 keyroostctl openpgp pin verify --pin env:BAD")
    assert info()["user_pin_retries"] == 1
    host.fail("BAD=000000 keyroostctl openpgp pin verify --pin env:BAD")
    assert info()["user_pin_retries"] == 0

    # PW1 is blocked, even the correct PIN fails
    host.fail("PIN=123456 keyroostctl openpgp pin verify --pin env:PIN")

    # Unblock PW1 using PW3
    keyroostctl("openpgp pin unblock --admin-pin env:ADMIN_PIN --new-pin env:NEW", NEW="654321")
    assert info()["user_pin_retries"] == 3
    keyroostctl("openpgp pin verify --pin env:PIN", PIN="654321")
  '';
}
