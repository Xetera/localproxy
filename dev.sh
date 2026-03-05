#!/usr/bin/env bash
sudo CGO_ENABLED=0 go run ./cmd/localproxyd --dns-server-port 53 --https-redirect --watch ~/projects $@
