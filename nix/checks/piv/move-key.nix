{
  testScript = ''
    # Generate a key in slot 9A (Authentication)
    keyroostctl("piv key generate --slot 9a --mgmt-key env:MGMT --yes")

    # Generate a key in slot 9C (Signature) to have two keys to move between
    keyroostctl("piv key generate --slot 9c --mgmt-key env:MGMT --yes")

    # Move the key from 9A to 9D (Key Management)
    keyroostctl("piv key move --from 9a --to 9d --mgmt-key env:MGMT")

    # Verify that 9A no longer has a key
    import json

    def info():
      (status, stdout) = host.execute("keyroostctl piv info --json")
      if status != 0:
        raise RuntimeError
      return json.loads(stdout)

    output = info()

    def get_slot(info, slot):
      for s in output["slots"]:
        if s["slot"] == slot:
          return s
      raise RuntimeError(f"slot not found {slot}")

    slot_9a = get_slot(output, "9a")
    assert slot_9a["key_present"] == False, "slot 9a should not have a key after move"

    slot_9d = get_slot(output, "9d")
    assert slot_9d["key_present"] == True, "slot 9d should have a key after move"

    # Move the key back from 9D to 9A to test bidirectional moves
    keyroostctl("piv key move --from 9d --to 9a --mgmt-key env:MGMT")

    output = info()
    slot_9a = get_slot(output, "9a")
    slot_9d = get_slot(output, "9d")
    assert slot_9a["key_present"] == True, "slot 9a should have a key after move back"
    assert slot_9d["key_present"] == False, "slot 9d should not have a key after move back"

    # Test delete: delete key from 9C
    keyroostctl("piv key delete --slot 9c --mgmt-key env:MGMT --yes")

    output = info()
    slot_9c = get_slot(output, "9c")
    assert slot_9c["key_present"] == False, "slot 9c should not have a key after delete"

    # Test error condition: try to move to an occupied slot (should fail)
    keyroostctl("piv key generate --slot 9e --mgmt-key env:MGMT --yes")
    # Try to move 9A to 9E (which is occupied) - this should fail
    host.fail("PIN=123456 MGMT=010203040506070801020304050607080102030405060708 keyroostctl piv key move --from 9a --to 9e --mgmt-key env:MGMT")
  '';
}
