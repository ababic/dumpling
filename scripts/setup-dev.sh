#!/usr/bin/env bash
# One-shot dev environment for Dumpling (Rust CLI + optional mdBook for docs).
# Safe to re-run; skips work that is already done.
#
# Usage: from repo root —  ./scripts/setup-dev.sh
#
# Environment:
#   MDBOOK_VERSION  — mdBook release tag (default: 0.4.52, matches CI docs workflow)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MDBOOK_VERSION="${MDBOOK_VERSION:-0.4.52}"
TOOLS_DIR="${ROOT}/.tools"
MDBOOK_BIN="${TOOLS_DIR}/mdbook"

require_rust() {
	if ! command -v rustc >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
		echo "error: rustc/cargo not found. Install Rust: https://rustup.rs/" >&2
		exit 1
	fi
}

mdbook_download_url() {
	local arch
	case "$(uname -sm)" in
	Linux\ x86_64) arch="x86_64-unknown-linux-gnu" ;;
	Darwin\ x86_64) arch="x86_64-apple-darwin" ;;
	Darwin\ arm64) arch="aarch64-apple-darwin" ;;
	*)
		echo "error: unsupported OS/arch for prebuilt mdbook: $(uname -sm)" >&2
		echo "Install mdbook yourself: https://github.com/rust-lang/mdBook/releases" >&2
		exit 1
		;;
	esac
	echo "https://github.com/rust-lang/mdBook/releases/download/v${MDBOOK_VERSION}/mdbook-v${MDBOOK_VERSION}-${arch}.tar.gz"
}

ensure_mdbook() {
	if [[ -x "${MDBOOK_BIN}" ]]; then
		installed="$("${MDBOOK_BIN}" --version 2>/dev/null | awk '{print $2}' || true)"
		if [[ "${installed}" == "${MDBOOK_VERSION}" ]]; then
			return 0
		fi
	fi

	mkdir -p "${TOOLS_DIR}"
	local url tmp
	url="$(mdbook_download_url)"
	tmp="$(mktemp -d)"
	trap 'rm -rf "${tmp}"' EXIT
	echo "Downloading mdbook v${MDBOOK_VERSION}…"
	curl -fsSL "${url}" | tar xz -C "${tmp}"
	mv "${tmp}/mdbook" "${MDBOOK_BIN}"
	chmod +x "${MDBOOK_BIN}"
	trap - EXIT
	rm -rf "${tmp}"
}

main() {
	require_rust

	if command -v rustup >/dev/null 2>&1; then
		echo "Installing stable toolchain + rustfmt + clippy (rustup)…"
		rustup toolchain install stable
		rustup component add rustfmt clippy --toolchain stable
	else
		echo "warning: rustup not found; ensure rustfmt and clippy are installed for stable CI parity." >&2
	fi

	echo "Prefetching crates (cargo fetch)…"
	cargo fetch

	ensure_mdbook
	echo "mdbook: ${MDBOOK_BIN} ($("${MDBOOK_BIN}" --version))"

	echo
	echo "Done. Typical checks:"
	echo "  cargo fmt --all -- --check"
	echo "  cargo clippy --all-targets --all-features"
	echo "  cargo test --all-targets --all-features"
	echo "  ${MDBOOK_BIN} build   # same as Docs CI (book.toml → docs/book)"
	echo
	echo "Tip: add ${TOOLS_DIR} to PATH for this shell:  export PATH=\"${TOOLS_DIR}:\${PATH}\""
}

main "$@"
