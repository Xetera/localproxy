#!/usr/bin/env bash
sudo CGO_ENABLED=0 go run ./cmd/localproxyd --watch ~/projects --https-redirect $@
