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
      propagatedBuildInputs = with pkgs.python3Packages; [
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
      dpt-rp1-py = pkgs.python3Packages.buildPythonApplication {
        inherit propagatedBuildInputs;

        pname = "dpt-rp1-py";
        version = "0.1.16";

        src = ./.;
        doCheck = false;

        pythonImportsCheck = ["dptrp1"];
      };
    in rec {
      devShell = pkgs.mkShell {
        inherit propagatedBuildInputs;
        nativeBuildInputs = [];
      };
      packages.default = dpt-rp1-py;
      apps = {
        dptrp1 = flake-utils.lib.mkApp {
          drv = packages.default;
          name = "dptrp1";
        };
        dptmount = flake-utils.lib.mkApp {
          drv = packages.default;
          name = "dptmount";
        };
        default = apps.dptrp1;
      };
    });
}
