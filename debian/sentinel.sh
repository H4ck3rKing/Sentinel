#!/bin/sh
# This script ensures the binaries installed by Sentinel's tools are in the PATH.

# Add Go's binary path
if command -v go >/dev/null 2>&1; then
    GOPATH=$(go env GOPATH)
    export PATH=$PATH:$GOPATH/bin
fi

# Add Pipx's binary path
export PATH=$PATH:$HOME/.local/bin 