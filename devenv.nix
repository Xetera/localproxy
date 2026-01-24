{ pkgs, ... }:

{
  env.CGO_ENABLED = 0 ;
  packages = [
    pkgs.git
    pkgs.mkcert
  ];
  languages.go.enable = true;
}
