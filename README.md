# Uptime Kuma Desktop

A native desktop client for [Uptime Kuma](https://github.com/louislam/uptime-kuma), built with Rust and [Iced](https://github.com/iced-rs/iced).

## Prerequisites

- **Rust**: Ensure you have the Rust toolchain installed.
- **Font**: This application uses **JetBrains Mono**. Please ensure it is installed on your system.

## Configuration

The application requires the following environment variables to connect to your Uptime Kuma instance:

- `UPTIME_KUMA_URL`: The URL of your Uptime Kuma instance (e.g., `https://status.example.com`).
- `UPTIME_KUMA_USERNAME`: Your username.
- `UPTIME_KUMA_PASSWORD`: Your password.

## Building and Running

### Development

To run the application in development mode:

```bash
export UPTIME_KUMA_URL="your_url"
export UPTIME_KUMA_USERNAME="your_username"
export UPTIME_KUMA_PASSWORD="your_password"
cargo run
```

### macOS App Bundle

To package the application as a standalone macOS App Bundle (which hides the terminal window):

1.  Export your environment variables in your terminal.
2.  Run the bundling script:

```bash
./bundle_macos.sh
```

This will create `UptimeKuma Desktop.app` in `target/release/MacOS`. The script "bakes" your current environment variables into a launcher script inside the app bundle, so you can launch it directly from Finder or Spotlight without needing to set environment variables system-wide.

**Note:** If your credentials change, you must re-run the `bundle_macos.sh` script.
