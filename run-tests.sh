#!/usr/bin/env bash

RED='\033[0;31m'
RESET='\033[0m'

# FIXME: need to wait for the `testapp` container to be ready for connections

go test -v ./...

if [ $? -ne 0 ]; then
  echo -e "\n${RED}One or more tests failed. If this is unexpected, it may be because the test server was still building.${RESET}"
fi

# exit the script with the exit code from `go test`
exit $?
