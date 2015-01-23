#!/bin/bash

TITAN_DIR="/usr/local/titan-0.5.3-hadoop2/bin"

# From: http://stackoverflow.com/a/246128
#   - To resolve finding the directory after symlinks
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
CURRENT="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

$TITAN_DIR/rexster.sh -s -c $CURRENT/rexster-config/rexster-inmemory.xml &