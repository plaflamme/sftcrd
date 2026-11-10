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
    name = "piv-puk-change";
    testScript = ''
      # PUK change: the same command with the PUK reference.
      keyroostctl("piv puk change --puk env:OLD --new-puk env:NEW", OLD="12345678", NEW="87654321")
      keyroostctl("piv puk change --puk env:OLD --new-puk env:NEW", OLD="87654321", NEW="12345678")
    '';
  }
