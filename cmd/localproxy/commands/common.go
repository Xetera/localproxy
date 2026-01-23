package commands

import (
	"os"
	"path/filepath"
)

func DataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".localproxy")
}

func PidFile() string {
	return filepath.Join(DataDir(), "daemon.pid")
}

func SocketPath() string {
	return filepath.Join(DataDir(), "daemon.sock")
}

func DBPath() string {
	return filepath.Join(DataDir(), "data.db")
}
