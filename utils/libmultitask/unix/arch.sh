#!/bin/sh
CC="$1"
shift
ARCH=$(exec "$CC" "${@}" -dumpmachine 2>/dev/null)
case "$ARCH" in
    x86_64*) echo "amd64" ;;
    i?86*) echo "386" ;;
    arm*) echo "arm" ;;
    *) echo "unknown-architecture" ;;
esac
