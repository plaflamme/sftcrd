{
  pkgs,
  keyroostctl,
  nixosModule,
}:
import ./make-piv-check.nix
  {
    inherit
      pkgs
      keyroostctl
      nixosModule
      ;
  }
  {
    name = "piv-info";
    testScript = ''
      keyroostctl("piv info | grep Serial: | grep 0x01020304")
    '';
  }
