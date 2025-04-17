package checkawscloudwatchlogsinsights

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/jessevdk/go-flags"
	"github.com/mackerelio/checkers"
	"github.com/mackerelio/golib/logging"
	"github.com/mackerelio/golib/pluginutil"
	"github.com/natefinch/atomic"
)

var logger *logging.Logger

func init() {
	logger = logging.GetLogger("checks.plugin.aws-cloudwatch-logs-insights")
	logging.SetLogLevel(logging.INFO)
}

// copy from check-aws-cloudwatch-logs
type logOpts struct {
	LogGroupNames []string `long:"log-group-name" required:"true" value-name:"LOG-GROUP-NAME" description:"Log group name" unquote:"false"`

	Filter        string `short:"f" long:"filter" required:"true" value-name:"FILTER" description:"Filter expression to use search logs via CloudWatch Logs Insights" unquote:"false"`
	WarningOver   int    `short:"w" long:"warning-over" value-name:"WARNING" description:"Trigger a warning if matched lines is over a number"`
	CriticalOver  int    `short:"c" long:"critical-over" value-name:"CRITICAL" description:"Trigger a critical if matched lines is over a number"`
	StateDir      string `short:"s" long:"state-dir" value-name:"DIR" description:"Dir to keep state files under" unquote:"false"`
	ReturnMessage bool   `short:"r" long:"return" description:"Output matched log messages (Up to 10 messages)"`
	Debug         bool   `long:"debug" description:"Enable debug log"`
}

type cwIface interface {
	StartQuery(ctx context.Context, params *cloudwatchlogs.StartQueryInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error)
	GetQueryResults(ctx context.Context, params *cloudwatchlogs.GetQueryResultsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error)
	StopQuery(ctx context.Context, params *cloudwatchlogs.StopQueryInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error)
}

type awsCWLogsInsightsPlugin struct {
	Service   cwIface
	StateFile string
	*logOpts
}

func newCWLogsInsightsPlugin(ctx context.Context, opts *logOpts, args []string) (*awsCWLogsInsightsPlugin, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	p := &awsCWLogsInsightsPlugin{logOpts: opts}
	p.Service = cloudwatchlogs.NewFromConfig(cfg)

	if p.StateDir == "" {
		workdir := pluginutil.PluginWorkDir()
		p.StateDir = filepath.Join(workdir, "check-aws-cloudwatch-logs-insights")
	}
	p.StateFile = getStateFile(p.StateDir, args)
	return p, nil
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
		msg += "\n" + strings.Join(res.ReturnedMessages, "\n")
	}
	return checkers.NewChecker(status, msg)
}

func (p *awsCWLogsInsightsPlugin) searchLogs(ctx context.Context, currentTimestamp time.Time, interval time.Duration) (*ParsedQueryResults, error) {
	// Considering delay in CloudWatch Logs Insights, endTime is 5 minutes prior current timestamp
	endTime := currentTimestamp.Add(-5 * time.Minute)
	startTime := endTime.Add(-1 * time.Minute)

	// If state file found, set startTime to last endTime
	lastState, err := p.loadState()
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load plugin state: %w", err)
	}
	if lastState != nil && lastState.EndTime != 0 {
		lastEndTime := time.Unix(lastState.EndTime, 0)
		// prevent too long duration
		if lastEndTime.Add(90 * time.Minute).Before(endTime) {
			logger.Warningf("ignoring stateFile since is's too old")
		} else {
			startTime = lastEndTime
		}
	}

	nextState := &logState{
		EndTime: endTime.Unix(),
	}

	queryID, err := p.startQuery(ctx, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to start query: %w", err)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			// Cancel current query.
			logger.Infof("execution cancelled. Will send StopQuery to stop the running query.")
			if saveStateErr := p.saveState(nextState); saveStateErr != nil {
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
			out, err := p.getQueryResults(ctx, queryID)
			if err != nil {
				logger.Warningf("GetQueryResults failed (will retry): %v", err)
				continue
			}
			res, err := parseResult(out)
			if err != nil {
				logger.Warningf("failed to parse GetQueryResults response (will retry): %v", err)
				continue
			}
			if !res.Finished {
				logger.Debugf("Query not finished. Will wait a while...")
				continue
			}
			logger.Debugf("Query finished! got result: %v", out)
			if res.FailureReason != "" {
				if saveStateErr := p.saveState(nextState); saveStateErr != nil {
					logger.Errorf("failed to save state file: %v", saveStateErr)
				}
				return nil, errors.New(res.FailureReason)
			}
			if saveStateErr := p.saveState(nextState); saveStateErr != nil {
				return nil, fmt.Errorf("failed to save state file: %w", saveStateErr)
			}
			return res, nil
		}
	}
}

// fullQuery returns p.Filter with additional commands for searching Logs
func (p *awsCWLogsInsightsPlugin) fullQuery() string {
	fullQuery := p.Filter
	// GetQueryResults returns @message (,@timestamp and @ptr) by default, but add `fields @message` explicitly for safety
	if p.ReturnMessage {
		fullQuery = fullQuery + " | fields @message"
	}
	return fullQuery
}

// startQuery calls cloudwatchlogs.StartQuery()
// returns (queryId, error)
func (p *awsCWLogsInsightsPlugin) startQuery(ctx context.Context, startTime, endTime time.Time) (*string, error) {
	input := &cloudwatchlogs.StartQueryInput{
		EndTime:       aws.Int64(endTime.Unix()),
		StartTime:     aws.Int64(startTime.Unix()),
		LogGroupNames: p.LogGroupNames,
		QueryString:   aws.String(p.fullQuery()),
		Limit:         aws.Int32(10),
	}
	logger.Debugf("start query, %v", input)
	q, err := p.Service.StartQuery(ctx, input)
	if err != nil {
		return nil, err
	}
	return q.QueryId, nil
}

// getQueryResults calls cloudwatchlogs.GetQueryResults()
func (p *awsCWLogsInsightsPlugin) getQueryResults(ctx context.Context, queryID *string) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	return p.Service.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{
		QueryId: queryID,
	})
}

// ParsedQueryResults is a result
type ParsedQueryResults struct {
	Finished         bool
	FailureReason    string
	MatchedCount     int
	ReturnedMessages []string
}

// parseResult parses *cloudwatchlogs.GetQueryResultsOutput for checking logs
func parseResult(out *cloudwatchlogs.GetQueryResultsOutput) (*ParsedQueryResults, error) {
	if out == nil {
		err := fmt.Errorf("unexpected response, %v", out)
		return nil, err
	}

	res := &ParsedQueryResults{}
	switch out.Status {
	case types.QueryStatusComplete:
		res.Finished = true
	case types.QueryStatusFailed, types.QueryStatusCancelled:
		res.Finished = true
		res.FailureReason = fmt.Sprintf("query was finished with `%s` status", out.Status)
	case types.QueryStatusRunning, types.QueryStatusScheduled:
		res.Finished = false
	default:
		return nil, fmt.Errorf("unexpected QueryStatus: %s", out.Status)
	}

	if out.Statistics != nil {
		res.MatchedCount = int(out.Statistics.RecordsMatched)
	}

	res.ReturnedMessages = []string{}
	for _, fields := range out.Results {
		for _, field := range fields {
			if field.Field != nil && *field.Field == "@message" && field.Value != nil {
				res.ReturnedMessages = append(res.ReturnedMessages, *field.Value)
				break
			}
		}
	}

	return res, nil
}

// stopQuery stops given query by cloudwatchlogs.StopQuery()
func (p *awsCWLogsInsightsPlugin) stopQuery(queryID *string) error {
	_, err := p.Service.StopQuery(context.Background(), &cloudwatchlogs.StopQueryInput{
		QueryId: queryID,
	})
	return err
}

type logState struct {
	EndTime int64
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
	res, err := p.searchLogs(ctx, now, 1*time.Second)
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

	if opts.Debug {
		logging.SetLogLevel(logging.DEBUG)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, err := newCWLogsInsightsPlugin(ctx, opts, args)
	if err != nil {
		return checkers.Unknown(err.Error())
	}

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
