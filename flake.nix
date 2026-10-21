{
  description = "ChatGPT Desktop by OpenAI, packaged from the official signed Linux .deb";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      # Only architectures that are genuinely built and gated natively in CI
      # appear here. Adding a system to this list without a native builder and
      # a runtime gate would advertise support that nothing verifies.
      systems = [ "x86_64-linux" "aarch64-linux" ];

      forAllSystems = fn:
        nixpkgs.lib.genAttrs systems (system: fn system);

      pkgsFor = system: import nixpkgs {
        inherit system;
        config.allowUnfreePredicate = pkg:
          builtins.elem (nixpkgs.lib.getName pkg) [ "chatgpt-desktop" ];
      };

      # The package always builds with patchelf 0.15.2, whatever nixpkgs this
      # flake follows. The reviewed interp-region invariant
      # (elf-baseline/interp-region-*.json) describes the space 0.15.2 vacates
      # in ChatGPT; 0.19.2 lays the file out differently, leaves a 0-byte
      # filler run, and the build's guard refuses it. That is the guard doing
      # its job. Drop or bump this pin only together with a re-reviewed
      # invariant, never on its own.
      patchelfFor = pkgs: pkgs.patchelf.overrideAttrs (finalAttrs: _: {
        version = "0.15.2";
        src = pkgs.fetchurl {
          url = "https://github.com/NixOS/patchelf/releases/download/${finalAttrs.version}/patchelf-${finalAttrs.version}.tar.bz2";
          hash = "sha256-F3RfVkFZyOIo/EEtplogSLhGxLa0Igt3y/IkFuAvLXw=";
        };
      });
    in
    {
      overlays.default = final: prev: {
        chatgpt-desktop = final.callPackage ./nix/package.nix {
          patchelf = patchelfFor final;
        };
      };

      packages = forAllSystems (system:
        let pkgs = pkgsFor system; in
        rec {
          chatgpt = pkgs.callPackage ./nix/package.nix {
            patchelf = patchelfFor pkgs;
          };
          default = chatgpt;
        });

      apps = forAllSystems (system: rec {
        chatgpt = {
          type = "app";
          program = "${self.packages.${system}.chatgpt}/bin/chatgpt";
          meta.description = "Launch ChatGPT Desktop";
        };
        default = chatgpt;
      });

      checks = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          chatgpt = self.packages.${system}.chatgpt;
        in
        (import ./nix/checks.nix { inherit pkgs chatgpt system self; })
        // { package = chatgpt; }
        # The NixOS VM test needs a machine of the same architecture to boot.
        # Advertising it for aarch64 while nothing can run it there claims a
        # gate that does not exist; the native ARM runner covers the same
        # ground with a direct bridge and launcher gate instead.
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          vm-smoke = import ./nix/vm-test.nix { inherit pkgs chatgpt; };
        });

      devShells = forAllSystems (system:
        let pkgs = pkgsFor system; in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              (python3.withPackages (ps: [ ps.zstandard ps.pyyaml ]))
              gnupg (patchelfFor pkgs) dpkg desktop-file-utils
              jq nix-prefetch bubblewrap
            ];
            shellHook = ''
              echo "chatgpt-desktop-nix dev shell"
              echo "  python3 tools/update.py --check   # signed update discovery"
              echo "  PYTHONPATH=\$PWD/tools:\$PWD python3 -m unittest discover -s tests"
              echo "  nix flake check                   # everything"
            '';
          };
        });

      formatter = forAllSystems (system: (pkgsFor system).nixpkgs-fmt);
    };
}
