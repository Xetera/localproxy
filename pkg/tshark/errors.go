package tshark

import "errors"

var ErrLayerNotFound = errors.New("layer not present in packet")
