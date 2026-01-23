#!/bin/sh
set -eu

DIR="${1:-${PROXYBUFF_CACHE_DIR:-/var/lib/proxybuff/cache}}"

if [ ! -d "$DIR" ]; then
	echo "cache dir does not exist: $DIR" >&2
	exit 0
fi

echo "clearing cache dir: $DIR" >&2

# Remove everything inside DIR (including dotfiles), but keep the directory itself.
rm -rf -- \
	"$DIR"/* \
	"$DIR"/.[!.]* \
	"$DIR"/..?* 2>/dev/null || true

