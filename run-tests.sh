#!/usr/bin/env bash

set -ex

go install "github.com/cucumber/godog/cmd/godog@latest"

# make sure all containers are ready -- just seeing if this works, there are better ways to wait
sleep 30

go test
