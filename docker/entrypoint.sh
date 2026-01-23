#!/bin/sh
set -eu

CONFIG_PATH="${PROXYBUFF_CONFIG_PATH:-/etc/proxybuff/config.json}"
DEFAULT_CACHE_DIR="${PROXYBUFF_CACHE_DIR:-/var/lib/proxybuff/cache}"

has_cache_dir=0
for a in "$@"; do
	case "$a" in
		--cache-dir|--cache-dir=*)
			has_cache_dir=1
			;;
	esac
done

mkdir -p "$(dirname "$CONFIG_PATH")" "$DEFAULT_CACHE_DIR"

if [ "$has_cache_dir" -eq 0 ]; then
	set -- --cache-dir "$DEFAULT_CACHE_DIR" "$@"
fi

exec /proxybuff --write-effective-config "$CONFIG_PATH" "$@"

