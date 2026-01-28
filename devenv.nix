{ pkgs, lib, ... }:

let
  envoy = import ./envoy.nix {
    inherit pkgs lib;
    stdenv = pkgs.stdenv;
  };
in
{
  env.CGO_ENABLED = 0;
  packages = [
    pkgs.git
    pkgs.mkcert
    envoy
  ];
  enterTest = ''
    envoy --version | grep envoy
  '';

  languages.go.enable = true;
}
