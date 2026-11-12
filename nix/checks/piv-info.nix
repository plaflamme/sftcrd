{
  imports = [ ./piv.nix ];
  testScript = ''
    keyroostctl("piv info | grep -i serial: | grep 0x01020304")
  '';
}
