{
  testScript = ''
    # PIN change: CHANGE REFERENCE verifies the old PIN.
    keyroostctl("piv pin change --pin env:OLD --new-pin env:NEW", OLD="123456", NEW="654321")
    keyroostctl("piv pin change --pin env:OLD --new-pin env:NEW", OLD="654321", NEW="123456")
  '';
}
