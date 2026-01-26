//go:build linux

package discovery

import "errors"

type ProcessWatcher struct{}

func NewProcessWatcher(basePaths []string) (*ProcessWatcher, error) {
	return nil, errors.New("process watcher not supported on linux")
}

func (w *ProcessWatcher) SetOnChange(fn func([]ListeningProcess)) {}

func (w *ProcessWatcher) SetOnWellKnownChange(fn func([]WellKnownProcess)) {}

func (w *ProcessWatcher) Start() error {
	return errors.New("process watcher not supported on linux")
}

func (w *ProcessWatcher) Stop() {}
