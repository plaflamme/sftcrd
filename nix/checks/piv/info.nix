{
  nodes.host.services.sftcrd.config = {
    serial = 43210;

    piv.pin = {
      value = "567123";
      max_tries = 2;
    };

    piv.slots = {
      "9c".key = "p256";
      "9d" = {
        key = ''
          -----BEGIN PRIVATE KEY-----
          MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYMU8CVjfJeB+70ru
          /NHmQO6CQSZFQmisQ79g//CB/4WhRANCAATHXXM5uR7Wo+zCW1bycqXoqy/9wRVQ
          v75NJ4SWaIbfBJB1wobcA3M3qcIhRgtE3dxX3MX9yxFBcF7JQ6X/bLfI
          -----END PRIVATE KEY-----
        '';
        cert = ''
          -----BEGIN CERTIFICATE-----
          MIIBfDCCASOgAwIBAgIUMXKZt0dmUfE2X2xvwgS2jme2SlcwCgYIKoZIzj0EAwIw
          FDESMBAGA1UEAwwJVGVzdCBQMjU2MB4XDTI2MTExNjIzMjA1NFoXDTI3MTExNjIz
          MjA1NFowFDESMBAGA1UEAwwJVGVzdCBQMjU2MFkwEwYHKoZIzj0CAQYIKoZIzj0D
          AQcDQgAEx11zObke1qPswltW8nKl6Ksv/cEVUL++TSeElmiG3wSQdcKG3ANzN6nC
          IUYLRN3cV9zF/csRQXBeyUOl/2y3yKNTMFEwHQYDVR0OBBYEFAKTdKwoRczwK2CM
          eWdSjePzTwTgMB8GA1UdIwQYMBaAFAKTdKwoRczwK2CMeWdSjePzTwTgMA8GA1Ud
          EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgbr2Vrt04qfVTfniWYaVIZHUT
          4sbPin4eBgn48tqnhKECIFmGGFkIJuy8rTq3zdj06vaFQtgf1aNqpWLeWxCxU4hy
          -----END CERTIFICATE-----
        '';
        pin_policy = "always";
        touch_policy = "always";
      };
    };
  };
  testScript = ''
    import json

    def info():
      (status, stdout) = host.execute("keyroostctl piv info --json")
      if status != 0:
        raise RuntimeError
      return json.loads(stdout)

    output = info()

    assert output["version"] == "5.7.4", f"Invalid version: {output['version']=}"
    assert output["serial"] == "43210", f"Invalid serial: {output['serial']=}"
    assert output["pin_retries"] == 2, f"Invalid pin_retries: {output['pin_retries']=}"

    def get_slot(info, slot):
      for s in output["slots"]:
        if s["slot"] == slot:
          return s
      raise RuntimeError(f"slot not found {slot}")

    slot_9d = get_slot(output, "9d")
    assert slot_9d["key_present"] == True, f"Invalid key_present: {slot_9d["key_present"]=}"
    assert slot_9d["cert_present"] == True, f"Invalid cert_present: {slot_9d["cert_present"]=}"
    # assert slot_9d["pin_policy"] == "always", f"Invalid pin_policy: {slot_9d["pin_policy"]=}"
    # assert slot_9d["touch_policy"] == "always", f"Invalid touch_policy: {slot_9d["touch_policy"]=}"

    slot_9c = get_slot(output, "9c")
    assert slot_9c["key_present"] == True, f"Invalid key_present: {slot_9c["key_present"]=}"
    assert slot_9c["cert_present"] == False, f"Invalid cert_present: {slot_9c["cert_present"]=}"

    slot_9a = get_slot(output, "9a")
    assert slot_9a["key_present"] == False
    assert slot_9a["cert_present"] == False

    keyroostctl("piv key generate --slot 9a --mgmt-key env:MGMT --yes")
    keyroostctl("piv cert generate --slot 9a --subject CN=foobar --pin env:PIN --mgmt-key env:MGMT --yes", PIN="567123")

    output = info()
    slot_9a = get_slot(output, "9a")
    assert slot_9a["key_present"] == True
    assert slot_9a["cert_present"] == True

  '';
}
