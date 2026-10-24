{
  description = "sparc32rt — SPARC V8 (LEON3/LEON4) to AArch64 Linux user-mode binary translator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      darwinSystem = "aarch64-darwin";
      darwinPkgs   = nixpkgs.legacyPackages.${darwinSystem};
      linuxSystem  = "x86_64-linux";
      linuxPkgs    = nixpkgs.legacyPackages.${linuxSystem};
      aarch64LinuxPkgs = nixpkgs.legacyPackages.aarch64-linux;

      # Cross-compilers for aarch64-unknown-linux-musl (sparc32rt itself)
      darwinA64Musl = darwinPkgs.pkgsCross.aarch64-multiplatform-musl;
      linuxA64Musl  = linuxPkgs.pkgsCross.aarch64-multiplatform-musl;

      mkSparc32rt = crossPkgs: crossPkgs.stdenv.mkDerivation {
        pname = "sparc32rt";
        version = "0.1.0";
        src = ./.;

        dontStrip = true;
        enableParallelBuilding = true;

        buildPhase = ''
          runHook preBuild
          CC="${crossPkgs.stdenv.cc.targetPrefix}gcc"
          command -v "$CC" >/dev/null 2>&1 || CC="${crossPkgs.stdenv.cc.targetPrefix}cc"
          make build CC="$CC"
          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall
          mkdir -p $out/bin $out/include
          cp _build/sparc32rt $out/bin/sparc32rt
          # argv0 alias for binfmt_misc registration (mirrors i686rt).
          ln -sf sparc32rt $out/bin/sparc32rt-binfmt-p
          cp include/a32host.h $out/include/a32host.h
          runHook postInstall
        '';

        meta = with crossPkgs.lib; {
          description = "Standalone static-PIE SPARC V8 -> AArch64 Linux user-mode translator";
          mainProgram = "sparc32rt";
          platforms = [ "aarch64-linux" ];
          license = licenses.asl20;
        };
      };

    in {
      packages.${darwinSystem} = {
        sparc32rt = mkSparc32rt darwinA64Musl;
        default   = self.packages.${darwinSystem}.sparc32rt;
      };

      checks.${darwinSystem} = {
        sparc32rt = self.packages.${darwinSystem}.sparc32rt;
      };

      packages.${linuxSystem} = {
        sparc32rt = mkSparc32rt linuxA64Musl;
        default   = self.packages.${linuxSystem}.sparc32rt;
      };

      checks.${linuxSystem} = {
        sparc32rt = self.packages.${linuxSystem}.sparc32rt;
      };

      packages.aarch64-linux = {
        sparc32rt = mkSparc32rt aarch64LinuxPkgs.pkgsMusl;
        default   = self.packages.aarch64-linux.sparc32rt;
      };

      checks.aarch64-linux = {
        sparc32rt = self.packages.aarch64-linux.sparc32rt;
      };

      # ── Hydra Jobs (ci.zw3rk.com) ───────────────────────────────────
      hydraJobs = {
        ${linuxSystem} = {
          sparc32rt = self.packages.${linuxSystem}.sparc32rt;
        };
        aarch64-linux = {
          sparc32rt = self.packages.aarch64-linux.sparc32rt;
        };
        ${darwinSystem} = {
          sparc32rt = self.packages.${darwinSystem}.sparc32rt;
        };
      };

      devShells.${darwinSystem}.default = darwinPkgs.mkShell {
        name = "sparc32rt-dev";
        buildInputs = [
          darwinPkgs.gnumake
          darwinA64Musl.stdenv.cc
        ];
      };
    };
}
