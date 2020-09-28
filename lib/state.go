package checkawscloudwatchlogsinsights

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/natefinch/atomic"
)

type logState struct {
	QueryStartedAt *int64
}

func getStateFile(stateDir string, args []string) string {
	return filepath.Join(
		stateDir,
		fmt.Sprintf(
			"%x.json",
			md5.Sum([]byte(
				strings.Join(
					[]string{
						os.Getenv("AWS_PROFILE"),
						os.Getenv("AWS_ACCESS_KEY_ID"),
						os.Getenv("AWS_REGION"),
						strings.Join(args, " "),
					},
					" ",
				)),
			),
		),
	)
}

func (p *awsCWLogsInsightsPlugin) loadState() (*logState, error) {
	f, err := os.Open(p.StateFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var s logState
	err = json.NewDecoder(f).Decode(&s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (p *awsCWLogsInsightsPlugin) saveState(s *logState) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(s); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.StateFile), 0755); err != nil {
		return err
	}
	return atomic.WriteFile(p.StateFile, &buf)
}
