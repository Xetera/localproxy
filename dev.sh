#!/bin/bash

pkill -f "go run.*localproxyd" 2>/dev/null
sleep 0.5

sudo CGO_ENABLED=0 go run ./cmd/localproxyd --watch ~/projects --https-redirect $@
