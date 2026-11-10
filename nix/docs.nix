{ pkgs, optionsDoc, ... }:
let
  ndgToml = pkgs.writeText "ndg.toml" ''
    title = "sftcrd Documentation"
    revision = "main"
    footer_text = "<a href=\"https://github.com/plaflamme/sftcrd\">sftcrd</a>"
  '';
in
pkgs.stdenv.mkDerivation {
  name = "sftcrd-docs";
  src = ../.;

  nativeBuildInputs = [ pkgs.ndg ];

  buildPhase = ''
    # Run NDG directly on the generated options.json
    # This will output a structured, complete HTML document set
    ndg --config-file ${ndgToml} \
      html \
      --module-options ${optionsDoc.optionsJSON}/share/doc/nixos/options.json \
      --options-filter-prefix services.sftcrd \
      --input-dir ./docs \
      --output-dir ./dist
  '';

  installPhase = ''
    mkdir -p $out
    cp -r dist/* $out/
  '';
}
