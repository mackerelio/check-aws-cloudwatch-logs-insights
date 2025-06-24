package checkawscloudwatchlogsinsights

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/natefinch/atomic"
)

type storeIface interface {
	Load() (*logState, error)
	Save(s *logState) error
}

type fileStore struct {
	StateFile string
}

func (p *fileStore) Load() (*logState, error) {
	f, err := os.Open(p.StateFile)
	if err != nil && os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var s logState
	err = json.NewDecoder(f).Decode(&s)
	if err != nil {
		return nil, err
	}
	logger.Debugf("Loaded state from stateFile %s: %#v", p.StateFile, s)
	return &s, nil
}

func (p *fileStore) Save(s *logState) error {
	logger.Debugf("Saving state to stateFile %s: %#v", p.StateFile, s)
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(s); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.StateFile), 0755); err != nil {
		return err
	}
	return atomic.WriteFile(p.StateFile, &buf)
}
