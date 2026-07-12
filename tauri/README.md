# rig-tauri

A desktop application for [rig](https://github.com/rig/rig) built with [Tauri](https://tauri.app/).

This app packages the rig web UI (bundled in the [rig](https://github.com/rig/rig) repo) with a bundled `rig-server` binary, providing a standalone desktop experience for rig.

> **Note**: This directory lives inside the [rig monorepo](https://github.com/rig/rig) under `tauri/`.
> Use the root `Makefile` targets (`make tauri-dev`, `make tauri-build`) to build from the repo root.

## Features

- 🖥️ Native desktop app with web UI
- 📦 Self-contained with bundled rig-server
- 🚀 No need to install Python or manage dependencies
- 🔧 All rig tools and capabilities available

## Prerequisites

- [Node.js](https://nodejs.org/) (for building)
- [Rust](https://rustup.rs/) (for Tauri)

## Development

From the **repo root**:

```bash
# Run in development mode (builds webui and starts Tauri dev server)
make tauri-dev
```

Or from the `tauri/` directory (after building webui once):

```bash
cd tauri
npm install
make dev
```

## Building

From the **repo root**:

```bash
# Build the sidecar (requires uv + pyinstaller)
make tauri-build-sidecar

# Build the app
make tauri-build
```

The built application will be in `tauri/src-tauri/target/release/bundle/`.

## Project Structure

- `src-tauri/` - Tauri backend (Rust): app lifecycle, server management, IPC
- `scripts/build-sidecar.sh` - Builds the rig-server binary for bundling
- `bins/` - Contains the bundled rig-server binary (gitignored)
- The webui is at `../webui/` (the rig monorepo's built-in webui)
