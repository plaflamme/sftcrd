{
  testScript = ''
    new_pin="654321"
    new_mgmt="080706050403020108070605040302010807060504030201"

    # Change the pin
    keyroostctl("piv pin change --pin env:PIN --new-pin env:NEW", NEW=new_pin)
    # Change the management key
    keyroostctl("piv mgmt-key change --mgmt-key env:MGMT --new-mgmt-key env:NEW", NEW=new_mgmt)

    # Prove the new values work
    keyroostctl("piv retries set --pin-tries 2 --puk-tries 2 --pin env:NEW_PIN --mgmt-key env:NEW_MGMT --yes", NEW_PIN=new_pin, NEW_MGMT=new_mgmt)

    # Factory reset: the host burns the PIN and PUK counters itself, then sends RESET.
    keyroostctl("piv reset --yes")

    # The card is back at factory state: the factory PIN and the factory management key work again.
    keyroostctl("piv retries set --pin-tries 2 --puk-tries 2 --pin env:PIN --mgmt-key env:MGMT --yes")
  '';
}
