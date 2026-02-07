package registry

import (
	"encoding/json"
	"fmt"
	"sync"

	bolt "go.etcd.io/bbolt"
)

var (
	projectsBucket          = []byte("projects")
	portsBucket             = []byte("ports")
	metaBucket              = []byte("meta")
	subdomainMappingsBucket = []byte("subdomain_mappings")
)

type SubdomainMapping struct {
	FolderGroup string `json:"folder_group"`
	Subdomain   string `json:"subdomain"`
	Cwd         string `json:"cwd"`
}

type Project struct {
	Name      string `json:"name"`
	Subdomain string `json:"subdomain"`
	Port      int    `json:"port"`
	Path      string `json:"path,omitempty"`
	Source    string `json:"source"`
	Container string `json:"container,omitempty"`
}

type Store struct {
	db       *bolt.DB
	mu       sync.RWMutex
	minPort  int
	maxPort  int
	onChange func()
}

func NewStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open bolt db: %w", err)
	}

	s := &Store{
		db:      db,
		minPort: 10000,
		maxPort: 20000,
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{projectsBucket, portsBucket, metaBucket, subdomainMappingsBucket} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	return s, nil
}

func (s *Store) SetOnChange(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = fn
}

func (s *Store) notifyChange() {
	if s.onChange != nil {
		s.onChange()
	}
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) AllocatePort() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var port int
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(portsBucket)
		used := make(map[int]bool)

		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			var p int
			fmt.Sscanf(string(k), "%d", &p)
			used[p] = true
		}

		for p := s.minPort; p <= s.maxPort; p++ {
			if !used[p] {
				port = p
				return b.Put([]byte(fmt.Sprintf("%d", p)), []byte("1"))
			}
		}
		return fmt.Errorf("no available ports in range %d-%d", s.minPort, s.maxPort)
	})

	return port, err
}

func (s *Store) ReleasePort(port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(portsBucket).Delete([]byte(fmt.Sprintf("%d", port)))
	})
}

func (s *Store) AddProject(p *Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(projectsBucket)
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}
		return b.Put([]byte(p.Name), data)
	})
	if err == nil {
		s.notifyChange()
	}
	return err
}

func (s *Store) RemoveProject(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var port int
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(projectsBucket)
		data := b.Get([]byte(name))
		if data != nil {
			var p Project
			if err := json.Unmarshal(data, &p); err == nil {
				port = p.Port
			}
		}
		return b.Delete([]byte(name))
	})
	if err == nil && port > 0 {
		s.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(portsBucket).Delete([]byte(fmt.Sprintf("%d", port)))
		})
		s.notifyChange()
	}
	return err
}

func (s *Store) GetProject(name string) (*Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var p Project
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(projectsBucket).Get([]byte(name))
		if data == nil {
			return fmt.Errorf("project %s not found", name)
		}
		return json.Unmarshal(data, &p)
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) ListProjects() ([]*Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var projects []*Project
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(projectsBucket)
		return b.ForEach(func(k, v []byte) error {
			var p Project
			if err := json.Unmarshal(v, &p); err != nil {
				return err
			}
			projects = append(projects, &p)
			return nil
		})
	})
	return projects, err
}

func (s *Store) GetProjectBySubdomain(subdomain string) (*Project, error) {
	projects, err := s.ListProjects()
	if err != nil {
		return nil, err
	}
	for _, p := range projects {
		if p.Subdomain == subdomain {
			return p, nil
		}
	}
	return nil, fmt.Errorf("no project with subdomain %s", subdomain)
}

func (s *Store) AddSubdomainMapping(m *SubdomainMapping) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(subdomainMappingsBucket)
		data, err := json.Marshal(m)
		if err != nil {
			return err
		}
		return b.Put([]byte(m.Cwd), data)
	})
	if err == nil {
		s.notifyChange()
	}
	return err
}

func (s *Store) RemoveSubdomainMapping(cwd string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(subdomainMappingsBucket).Delete([]byte(cwd))
	})
	if err == nil {
		s.notifyChange()
	}
	return err
}

func (s *Store) GetMappingsForFolder(folderGroup string) ([]*SubdomainMapping, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var mappings []*SubdomainMapping
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(subdomainMappingsBucket)
		return b.ForEach(func(k, v []byte) error {
			var m SubdomainMapping
			if err := json.Unmarshal(v, &m); err != nil {
				return err
			}
			if m.FolderGroup == folderGroup {
				mappings = append(mappings, &m)
			}
			return nil
		})
	})
	return mappings, err
}

func (s *Store) ListMappings() ([]*SubdomainMapping, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var mappings []*SubdomainMapping
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(subdomainMappingsBucket)
		return b.ForEach(func(k, v []byte) error {
			var m SubdomainMapping
			if err := json.Unmarshal(v, &m); err != nil {
				return err
			}
			mappings = append(mappings, &m)
			return nil
		})
	})
	return mappings, err
}

func (s *Store) GetMappingByCwd(cwd string) (*SubdomainMapping, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var m SubdomainMapping
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(subdomainMappingsBucket).Get([]byte(cwd))
		if data == nil {
			return fmt.Errorf("mapping for %s not found", cwd)
		}
		return json.Unmarshal(data, &m)
	})
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Store) AddSubdomainMappingData(folderGroup, subdomain, cwd string) error {
	return s.AddSubdomainMapping(&SubdomainMapping{
		FolderGroup: folderGroup,
		Subdomain:   subdomain,
		Cwd:         cwd,
	})
}

func (s *Store) GetMappingSubdomainsByCwd(folderGroup string) (map[string]string, error) {
	mappings, err := s.GetMappingsForFolder(folderGroup)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string)
	for _, m := range mappings {
		result[m.Cwd] = m.Subdomain
	}
	return result, nil
}
