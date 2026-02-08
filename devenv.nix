{ pkgs, ... }:

{
  env.CGO_ENABLED = 0;
  packages = [
    pkgs.git
  ];

  languages.go.enable = true;
}
