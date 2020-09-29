package checkawscloudwatchlogsinsights

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
	"github.com/jessevdk/go-flags"
	"github.com/mackerelio/checkers"
	"github.com/mackerelio/golib/logging"
	"github.com/mackerelio/golib/pluginutil"
	"github.com/natefinch/atomic"
)

var logger *logging.Logger

func init() {
	logger = logging.GetLogger("checks.plugin.aws-cloudwatch-logs-insights")
	logging.SetLogLevel(logging.DEBUG) // TODO: disable debug log
}

// copy from check-aws-cloudwatch-logs
type logOpts struct {
	LogGroupNames []string `long:"log-group-name" required:"true" value-name:"LOG-GROUP-NAME" description:"Log group name" unquote:"false"`

	Filter        string `short:"f" long:"filter" required:"true" value-name:"FILTER" description:"Filter expression to use search logs via CloudWatch Logs Insights" unquote:"false"`
	WarningOver   int    `short:"w" long:"warning-over" value-name:"WARNING" description:"Trigger a warning if matched lines is over a number"`
	CriticalOver  int    `short:"c" long:"critical-over" value-name:"CRITICAL" description:"Trigger a critical if matched lines is over a number"`
	StateDir      string `short:"s" long:"state-dir" value-name:"DIR" description:"Dir to keep state files under" unquote:"false"`
	ReturnMessage bool   `short:"r" long:"return" description:"Output earliest log found with given query"`
}

type awsCWLogsInsightsPlugin struct {
	Service   cloudwatchlogsiface.CloudWatchLogsAPI
	StateFile string
	*logOpts
}

func newCWLogsInsightsPlugin(opts *logOpts, args []string) (*awsCWLogsInsightsPlugin, error) {
	var err error
	p := &awsCWLogsInsightsPlugin{logOpts: opts}
	p.Service, err = createService(opts)
	if err != nil {
		return nil, err
	}
	if p.StateDir == "" {
		workdir := pluginutil.PluginWorkDir()
		p.StateDir = filepath.Join(workdir, "check-aws-cloudwatch-logs-insights")
	}
	p.StateFile = getStateFile(p.StateDir, args)
	return p, nil
}

func createService(opts *logOpts) (*cloudwatchlogs.CloudWatchLogs, error) {
	sess, err := session.NewSession()
	if err != nil {
		return nil, err
	}
	return cloudwatchlogs.New(sess, aws.NewConfig()), nil
}

func (p *awsCWLogsInsightsPlugin) buildChecker(res *ParsedQueryResults) *checkers.Checker {
	status := checkers.OK
	var msg string
	if res.MatchedCount > p.CriticalOver {
		status = checkers.CRITICAL
		msg = fmt.Sprintf("%d > %d messages", res.MatchedCount, p.CriticalOver)
	} else if res.MatchedCount > p.WarningOver {
		status = checkers.WARNING
		msg = fmt.Sprintf("%d > %d messages", res.MatchedCount, p.WarningOver)
	} else {
		msg = fmt.Sprintf("%d messages", res.MatchedCount)
	}
	if status != checkers.OK && p.ReturnMessage {
		msg += "\n" + res.ReturnedMessage
	}
	return checkers.NewChecker(status, msg)
}

func (p *awsCWLogsInsightsPlugin) searchLogs(ctx context.Context, currentTimestamp time.Time) (*ParsedQueryResults, error) {
	var startTime time.Time
	if lastState, err := p.loadState(); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load plugin state: %w", err)
		}
	} else if lastState.QueryStartedAt != 0 {
		startTime = time.Unix(lastState.QueryStartedAt, 0).Add(-2 * time.Minute)
	}

	endTime := currentTimestamp
	if startTime.IsZero() {
		startTime = endTime.Add(-3 * time.Minute)
	}
	state := &logState{
		QueryStartedAt: currentTimestamp.Unix(),
	}

	queryID, err := p.startQuery(startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to start query: %w", err)
	}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			// Cancel current query.
			logger.Infof("execution cancelled. Will send StopQuery to stop the running query.")
			if saveStateErr := p.saveState(state); saveStateErr != nil {
				logger.Errorf("failed to save state file: %v", saveStateErr)
			}
			if stopQueryErr := p.stopQuery(queryID); stopQueryErr != nil {
				logger.Errorf("failed to stop the running query: %v", stopQueryErr)
			} else {
				logger.Debugf("succeeded to cancel query")
			}
			return nil, err
		case <-ticker.C:
			logger.Debugf("Try to GetQueryResults...")
			out, err := p.getQueryResults(queryID)
			if err != nil {
				logger.Warningf("GetQueryResults failed (will retry): %v", err)
				continue
			}
			res, err := parseResult(out)
			if res.Finished {
				logger.Debugf("Query finished! got result: %v", out)
				if err != nil {
					if saveStateErr := p.saveState(state); saveStateErr != nil {
						logger.Errorf("failed to save state file: %v", saveStateErr)
					}
					return nil, fmt.Errorf("failed to get query results: %w", err)
				}
				if saveStateErr := p.saveState(state); saveStateErr != nil {
					return nil, fmt.Errorf("failed to save state file: %w", saveStateErr)
				}
				return res, nil
			}
			logger.Debugf("Query not finished. Will wait a while...")
		}
	}
}

// fullQuery returns p.Filter with additional commands for searching Logs
func (p *awsCWLogsInsightsPlugin) fullQuery() string {
	fullQuery := p.Filter
	if p.ReturnMessage {
		fullQuery = fullQuery + "| stats earliest(@message)"
	}
	return fullQuery
}

// startQuery calls cloudwatchlogs.StartQuery()
// returns (queryId, error)
func (p *awsCWLogsInsightsPlugin) startQuery(startTime, endTime time.Time) (*string, error) {
	q, err := p.Service.StartQuery(&cloudwatchlogs.StartQueryInput{
		EndTime:       aws.Int64(endTime.Unix()),
		StartTime:     aws.Int64(startTime.Unix()),
		LogGroupNames: aws.StringSlice(p.LogGroupNames),
		QueryString:   aws.String(p.fullQuery()),
		Limit:         aws.Int64(1),
	})
	if err != nil {
		return nil, err
	}
	return q.QueryId, nil
}

// getQueryResults calls cloudwatchlogs.GetQueryResults()
func (p *awsCWLogsInsightsPlugin) getQueryResults(queryID *string) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	return p.Service.GetQueryResults(&cloudwatchlogs.GetQueryResultsInput{
		QueryId: queryID,
	})
}

// ParsedQueryResults is a result
type ParsedQueryResults struct {
	Finished        bool
	MatchedCount    int
	ReturnedMessage string
}

// parseResult parses *cloudwatchlogs.GetQueryResultsOutput for checking logs
func parseResult(out *cloudwatchlogs.GetQueryResultsOutput) (*ParsedQueryResults, error) {
	if out == nil || out.Status == nil {
		err := fmt.Errorf("unexpected response, %v", out)
		return nil, err
	}

	res := &ParsedQueryResults{}
	switch *out.Status {
	case cloudwatchlogs.QueryStatusComplete, cloudwatchlogs.QueryStatusFailed, cloudwatchlogs.QueryStatusCancelled:
		res.Finished = true
	}

	if out.Statistics != nil && out.Statistics.RecordsMatched != nil {
		res.MatchedCount = int(*out.Statistics.RecordsMatched)
	}

	for _, fields := range out.Results {
		for _, field := range fields {
			if field.Field != nil && *field.Field == "earliest(@message)" && field.Value != nil {
				res.ReturnedMessage = *(field.Value)
				break
			}
		}
	}

	return res, nil
}

// stopQuery stops given query by cloudwatchlogs.StopQuery()
func (p *awsCWLogsInsightsPlugin) stopQuery(queryID *string) error {
	_, err := p.Service.StopQuery(&cloudwatchlogs.StopQueryInput{
		QueryId: queryID,
	})
	return err
}

type logState struct {
	QueryStartedAt int64
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
	logger.Debugf("Loaded state from stateFile %s: %#v", p.StateFile, s)
	return &s, nil
}

func (p *awsCWLogsInsightsPlugin) saveState(s *logState) error {
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

func (p *awsCWLogsInsightsPlugin) run(ctx context.Context) *checkers.Checker {
	now := time.Now()
	res, err := p.searchLogs(ctx, now)
	if err != nil {
		return checkers.Unknown(err.Error())
	}
	return p.buildChecker(res)
}

// Do the logic
func Do() {
	ckr := run(os.Args[1:])
	ckr.Name = "CloudWatch Logs Insights"
	ckr.Exit()
}

func run(args []string) *checkers.Checker {
	opts := &logOpts{}
	_, err := flags.ParseArgs(opts, args)
	if err != nil {
		os.Exit(1)
	}
	p, err := newCWLogsInsightsPlugin(opts, args)
	if err != nil {
		return checkers.Unknown(err.Error())
	}

	ctx, cancel := context.WithCancel(context.Background())

	// on termination, call cancel
	resCh := make(chan *checkers.Checker, 1)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, os.Interrupt)
	go func() {
		resCh <- p.run(ctx)
	}()
	select {
	case res := <-resCh:
		cancel() // avoid context leak
		return res
	case <-sigCh:
		cancel()
		select {
		case res := <-resCh:
			return res
		case <-sigCh:
			logger.Errorf("Received signal again. force shutdown.")
			return checkers.Unknown("terminated by signal")
		}
	}
}
