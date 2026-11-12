{
  testScript = ''
    import json

    def info():
      (status, stdout) = host.execute("keyroostctl piv info --json")
      if status != 0:
        raise RuntimeError
      return json.loads(stdout)

    output = info()

    assert output["version"] == "5.7.4"
    assert output["serial"] == "87654321"
    assert output["pin_retries"] == 5

    def get_slot(info, slot):
      for s in output["slots"]:
        if s["slot"] == slot:
          return s
      raise RuntimeError(f"slot not found {slot}")

    slot_9a = get_slot(output, "9a")
    assert slot_9a["key_present"] == False
    assert slot_9a["cert_present"] == False

    keyroostctl("piv key generate --slot 9a --mgmt-key env:MGMT --yes")
    keyroostctl("piv cert generate --slot 9a --subject CN=foobar --pin env:PIN --mgmt-key env:MGMT --yes")

    output = info()
    slot_9a = get_slot(output, "9a")
    assert slot_9a["key_present"] == True
    assert slot_9a["cert_present"] == True

  '';
}
