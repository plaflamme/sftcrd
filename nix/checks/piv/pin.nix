{
  testScript = ''
    # PIN change
    keyroostctl("piv pin change --pin env:OLD --new-pin env:NEW", OLD="123456", NEW="654321")
    keyroostctl("piv pin change --pin env:OLD --new-pin env:NEW", OLD="654321", NEW="123456")

    # PUK change
    keyroostctl("piv puk change --puk env:OLD --new-puk env:NEW", OLD="12345678", NEW="87654321")
    keyroostctl("piv puk change --puk env:OLD --new-puk env:NEW", OLD="87654321", NEW="12345678")

    # Block the PIN: five wrong old PINs, each burning one try.
    host.fail("BAD=000000 NEW=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:NEW")
    host.fail("BAD=000000 NEW=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:NEW")
    host.fail("BAD=000000 NEW=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:NEW")
    host.fail("BAD=000000 NEW=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:NEW")
    host.fail("BAD=000000 NEW=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:NEW")

    # PIN is blocked
    host.fail("PIN=123456 NEW=654321 keyroostctl piv pin change --pin env:PIN --new-pin env:NEW")
    # Unblock
    keyroostctl("piv pin unblock --puk env:PUK --new-pin env:NEW", PUK="12345678", NEW="654321")
    # PIN is unblocked
    keyroostctl("piv pin change --pin env:OLD --new-pin env:NEW", OLD="654321", NEW="123456")

    # Block the PUK
    host.fail("BAD=00000000 NEW=00000000 keyroostctl piv puk change --puk env:BAD --new-puk env:NEW")
    host.fail("BAD=00000000 NEW=00000000 keyroostctl piv puk change --puk env:BAD --new-puk env:NEW")
    host.fail("BAD=00000000 NEW=00000000 keyroostctl piv puk change --puk env:BAD --new-puk env:NEW")

    # PUK is blocked
    host.fail("PIN=12345678 NEW=87654321 keyroostctl piv puk change --puk env:PIN --new-puk env:NEW")
  '';
}
