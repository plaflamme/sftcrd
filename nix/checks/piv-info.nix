{
  pkgs,
  keyroost,
  sftcrd,
  system,
}:

import ./make-piv-check.nix
  {
    inherit
      pkgs
      keyroost
      sftcrd
      system
      ;
  }
  {
    name = "piv-info";
    testScript = ''
      keyroostctl("piv info | grep Serial: | grep 0x01020304")
    '';
  }
