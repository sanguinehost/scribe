{ pkgs, ... }: {
  # Which nixpkgs channel to use.
  channel = "unstable"; # Keep unstable channel

  # Use https://search.nixos.org/packages to find packages
  packages = [
    pkgs.rustup # Add the Rust toolchain
    pkgs.gcc    # Add the C compiler/linker
    pkgs.nodejs_20 # Add Node.js v20
    pkgs.nodePackages.pnpm # Add pnpm
    pkgs.pkg-config # Needed by build scripts
    pkgs.openssl.dev # Needed for openssl-sys
    pkgs.postgresql # Keep the main package for runtime/tools/service
    pkgs.libpq      # Use the dedicated libpq package
    # pkgs.go
    # pkgs.python311
    # pkgs.python311Packages.pip
    # pkgs.nodePackages.nodemon
  ];

  # Sets environment variables in the workspace
  env = {
    # Explicitly add the libpq library path to the linker flags
    NIX_LDFLAGS = "-L${pkgs.libpq}/lib";
    LIBRARY_PATH = "${pkgs.libpq}/lib"; # Also set standard LIBRARY_PATH
  };
  idx = {
    # Search for the extensions you want on https://devenv.sh/extensions/
    extensions = [
      "rust" # Enables Rust support
      "nodejs" # Enables NodeJS support
      # "go"
      # "python"
      # "java"
    ];
    # Enable previews and customize configuration
    previews = {
      enable = true;
      # Previews should be an attribute set (object), not a list
      previews = {
        backend = {
          manager = "web"; # Added manager
          # Use 'cwd' instead of 'workingDirectory'
          cwd = "backend";
          # Use 'command' (a list of strings) instead of 'start'
          command = [ "sh" "-c" "DATABASE_URL=postgres://postgres:password@localhost:5432/postgres RUST_LOG=info cargo run" ];
          env = {
             # Example: Set RUST_LOG level specifically for this preview
             RUST_LOG = "info,sqlx=warn"; # Adjust log levels as needed
             DATABASE_URL = "postgres://postgres:password@localhost:5432/postgres"; # Updated DB name to default 'postgres'
           };
        };
        frontend = {
          manager = "web"; # Added manager
          # Use 'cwd' instead of 'workingDirectory'
          cwd = "frontend";
          # Use 'command' (a list of strings) instead of 'start'
          command = [ "sh" "-c" "pnpm run dev -- --port $PORT" ]; # Use sh -c here too
           # env = {
           #   # Example: Set specific env vars for the frontend preview
           #   PUBLIC_API_URL = "http://localhost:3000";
           # };
        };
      };
    };
    # Workspace lifecycle hooks
    workspace = {
      # Runs when the workspace is opened / resumed
      onCreate = {
        # Example: install dependencies when the workspace starts
        # frontend-install = "cd frontend && pnpm install";
        # backend-build = "cd backend && cargo build";
      };
      # Runs when the workspace is stopped or closed
    };
  };
  # Use services to start your database or other services
  services.postgres = {
    enable = true;
    package = pkgs.postgresql; # Ensure this matches the version in 'packages' if specified differently
    # Other postgres options can be configured here
    # extensions = [ "pgvector" ]; # Example: Enable extensions like pgvector
  };
  # services.redis.enable = true;
}
