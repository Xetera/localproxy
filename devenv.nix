{
  pkgs,
  lib,
  config,
  inputs,
  ...
}:

{
  # https://devenv.sh/basics/
  env.GREET = "devenv";

  env.CGO_ENABLED = 0 ;
  # https://devenv.sh/packages/
  packages = [
    pkgs.git
    pkgs.mkcert
  ];
  # ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
  #   pkgs.libresolv
  #   pkgs.apple-sdk
  # ];

  # https://devenv.sh/languages/
  languages.go.enable = true;
  scripts.hello.exec = ''
    echo hello from $GREET
  '';

  # https://devenv.sh/basics/
  enterShell = ''
    hello         # Run scripts directly
    git --version # Use packages
  '';

  enterTest = ''
    echo "Running tests"
    git --version | grep --color=auto "${pkgs.git.version}"
  '';
}
