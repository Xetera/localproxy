package discovery

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/xetera/localproxy/internal/config"
)

type FileProject struct {
	Path      string
	Name      string
	Subdomain string
	Port      int
}

type FilesystemWatcher struct {
	watcher   *fsnotify.Watcher
	paths     map[string]bool
	mu        sync.RWMutex
	onChange  func([]FileProject)
	done      chan struct{}
}

func NewFilesystemWatcher() (*FilesystemWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &FilesystemWatcher{
		watcher: watcher,
		paths:   make(map[string]bool),
		done:    make(chan struct{}),
	}, nil
}

func (w *FilesystemWatcher) SetOnChange(fn func([]FileProject)) {
	w.onChange = fn
}

func (w *FilesystemWatcher) AddPath(path string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	if w.paths[absPath] {
		return nil
	}

	if err := w.watcher.Add(absPath); err != nil {
		return err
	}

	w.paths[absPath] = true
	w.notifyChange()
	return nil
}

func (w *FilesystemWatcher) RemovePath(path string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	if !w.paths[absPath] {
		return nil
	}

	w.watcher.Remove(absPath)
	delete(w.paths, absPath)
	w.notifyChange()
	return nil
}

func (w *FilesystemWatcher) Start() error {
	go w.watchLoop()
	w.notifyChange()
	return nil
}

func (w *FilesystemWatcher) Stop() {
	close(w.done)
	w.watcher.Close()
}

func (w *FilesystemWatcher) watchLoop() {
	for {
		select {
		case <-w.done:
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			if filepath.Base(event.Name) == config.ConfigFileName {
				w.notifyChange()
			}
		case <-w.watcher.Errors:
		}
	}
}

func (w *FilesystemWatcher) notifyChange() {
	if w.onChange == nil {
		return
	}

	projects := w.ListProjects()
	w.onChange(projects)
}

func (w *FilesystemWatcher) ListProjects() []FileProject {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var projects []FileProject
	for path := range w.paths {
		cfg, err := config.LoadConfig(path)
		if err != nil {
			continue
		}

		projects = append(projects, FileProject{
			Path:      path,
			Name:      cfg.Name,
			Subdomain: cfg.Subdomain,
			Port:      cfg.Port,
		})
	}
	return projects
}

func (w *FilesystemWatcher) GetPaths() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var paths []string
	for p := range w.paths {
		paths = append(paths, p)
	}
	return paths
}

func (w *FilesystemWatcher) LoadFromStore(paths []string) error {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			w.AddPath(p)
		}
	}
	return nil
}
