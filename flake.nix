{
  description = "A basic flake with a shell";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in rec {
      packages.default = pkgs.python3Packages.buildPythonApplication {
        pname = "dpt-rp1-py";
        version = "0.1.16";

        src = ./.;
        doCheck = false;

        propagatedBuildInputs = with python3Packages; [
          anytree
          fusepy
          httpsig
          pbkdf2
          pyyaml
          requests
          setuptools
          tqdm
          urllib3
          zeroconf
        ];

        pythonImportsCheck = ["dptrp1"];
      };
      apps.default = flake-utils.lib.mkApp {drv = packages.default;};
    });
}
