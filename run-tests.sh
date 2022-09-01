#!/usr/bin/env bash

set -ex

go install "github.com/cucumber/godog/cmd/godog@latest"

go test
