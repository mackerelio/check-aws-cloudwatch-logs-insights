package checkawscloudwatchlogsinsights

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
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
)

var logger *logging.Logger

func init() {
	logger = logging.GetLogger("checks.plugin.aws-cloudwatch-logs-insights")
	logging.SetLogLevel(logging.DEBUG)
}

// copy from check-aws-cloudwatch-logs
type logOpts struct {
	LogGroupNames []string `long:"log-group-name" required:"true" value-name:"LOG-GROUP-NAME" description:"Log group name" unquote:"false"`

	Query         string `short:"q" long:"query" required:"true" value-name:"QUERY" description:"Partial query used for CloudWatch Logs Insights" unquote:"false"`
	WarningOver   int    `short:"w" long:"warning-over" value-name:"WARNING" description:"Trigger a warning if matched lines is over a number"`
	CriticalOver  int    `short:"c" long:"critical-over" value-name:"CRITICAL" description:"Trigger a critical if matched lines is over a number"`
	StateDir      string `short:"s" long:"state-dir" value-name:"DIR" description:"Dir to keep state files under" unquote:"false"`
	ReturnContent bool   `short:"r" long:"return" description:"Output matched lines"`
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
	// state not implemented
	if p.StateDir == "" {
		workdir := pluginutil.PluginWorkDir()
		p.StateDir = filepath.Join(workdir, "check-aws-cloudwatch-logs-insights")
	}
	// p.StateFile = getStateFile(p.StateDir, opts.LogGroupName, opts.LogStreamNamePrefix, args)
	return p, nil
}

func createService(opts *logOpts) (*cloudwatchlogs.CloudWatchLogs, error) {
	sess, err := session.NewSession()
	if err != nil {
		return nil, err
	}
	return cloudwatchlogs.New(sess, aws.NewConfig()), nil
}

func (p *awsCWLogsInsightsPlugin) checkCount(count int) *checkers.Checker {
	status := checkers.OK
	var msg string
	if count > p.CriticalOver {
		status = checkers.CRITICAL
		msg = fmt.Sprintf("%d > %d messages", count, p.CriticalOver)
	} else if count > p.WarningOver {
		status = checkers.WARNING
		msg = fmt.Sprintf("%d > %d messages", count, p.WarningOver)
	} else {
		msg = fmt.Sprintf("%d messages", count)
	}
	return checkers.NewChecker(status, msg)
}

func (p *awsCWLogsInsightsPlugin) collectCount(ctx context.Context) (int, error) {
	endTime := time.Now()
	startTime := endTime.Add(-2 * time.Minute)
	queryID, err := p.startQuery(startTime, endTime)
	if err != nil {
		return 0, fmt.Errorf("failed to start query: %w", err)
	}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			err := ctx.Err()
			// Cancel current query.
			logger.Infof("execution cancelled. Will send StopQuery to stop the running query.")
			stopQueryErr := p.stopQuery(queryID)
			if stopQueryErr != nil {
				return 0, fmt.Errorf("execution cancelled (%v) and failed to stop the runnig query: %w", err, stopQueryErr)
			}
			logger.Debugf("succeeded to cancel query")
			return 0, err
		case <-ticker.C:
			logger.Debugf("Try to GetQueryResults...")
			res, finished, err := p.getQueryResults(queryID)
			if finished {
				logger.Debugf("Query finished! got result: %v", res)
				if err != nil {
					return 0, fmt.Errorf("failed to get query results: %w", err)
				}
				return extractCount(res)
			}
			if err != nil {
				logger.Errorf("GetQueryResults failed (will retry): %v", err)
			} else {
				logger.Debugf("Query not finished. Will wait a while...")
			}
		}
	}
}

// QueryLimit is limit for StartQuery
const QueryLimit = 100

// startQuery calls cloudwatchlogs.StartQuery()
// returns (queryId, error)
func (p *awsCWLogsInsightsPlugin) startQuery(startTime, endTime time.Time) (*string, error) {
	q, err := p.Service.StartQuery(&cloudwatchlogs.StartQueryInput{
		EndTime:       aws.Int64(endTime.Unix()),
		StartTime:     aws.Int64(startTime.Unix()),
		LogGroupNames: aws.StringSlice(p.LogGroupNames),
		QueryString:   aws.String(p.Query),
		Limit:         aws.Int64(QueryLimit),
	})
	if err != nil {
		return nil, err
	}
	return q.QueryId, nil
}

// getQueryResults calls cloudwatchlogs.GetQueryResults()
// returns (results, finished, error)
// if finished is false, the query is not finished (scheduled or running).
// otherwise the query is finished (complete, failed, cancelled)
func (p *awsCWLogsInsightsPlugin) getQueryResults(queryID *string) ([][]*cloudwatchlogs.ResultField, bool, error) {
	res, err := p.Service.GetQueryResults(&cloudwatchlogs.GetQueryResultsInput{
		QueryId: queryID,
	})
	if err != nil {
		return nil, false, err
	}
	if res == nil || res.Status == nil {
		return nil, false, errors.New("failed to get response")
	}
	finished := false
	switch *res.Status {
	case cloudwatchlogs.QueryStatusComplete, cloudwatchlogs.QueryStatusFailed, cloudwatchlogs.QueryStatusCancelled:
		finished = true
	}

	// XXX Do we need Statistics?
	return res.Results, finished, err
}

// parseResult parses *cloudwatchlogs.GetQueryResultsOutput for checking logs
// returns (matchedLogCount, queryHasFinished, error)
func parseResult(res *cloudwatchlogs.GetQueryResultsOutput) (int, bool, error) {
	if res == nil || res.Status == nil || res.Statistics == nil {
		return 0, false, fmt.Errorf("unexpected response, %v", res)
	}

	finished := false
	switch *res.Status {
	case cloudwatchlogs.QueryStatusComplete, cloudwatchlogs.QueryStatusFailed, cloudwatchlogs.QueryStatusCancelled:
		finished = true
	}
	if !finished {
		return 0, false, nil
	}

	count := int(*res.Statistics.RecordsMatched)

	return count, finished, nil
}

// stopQuery stops given query by cloudwatchlogs.StopQuery()
func (p *awsCWLogsInsightsPlugin) stopQuery(queryID *string) error {
	_, err := p.Service.StopQuery(&cloudwatchlogs.StopQueryInput{
		QueryId: queryID,
	})
	return err
}

// extractCount extracts integer value from [0][0] of given response.
// therefore, res[0][0] must be accessible and parsable as number.
func extractCount(res [][]*cloudwatchlogs.ResultField) (int, error) {
	if len(res) == 0 {
		return 0, errors.New("result is empty")
	}
	record := res[0]
	if len(record) == 0 || record[0] == nil || record[0].Value == nil {
		return 0, fmt.Errorf("unknown format: %#v", record)
	}
	cntStr := *record[0].Value
	return strconv.Atoi(cntStr)
}

func (p *awsCWLogsInsightsPlugin) runWithoutContent(ctx context.Context) *checkers.Checker {
	count, err := p.collectCount(ctx)
	if err != nil {
		return checkers.Unknown(err.Error())
	}
	return p.checkCount(count)
}

func (p *awsCWLogsInsightsPlugin) run(ctx context.Context) *checkers.Checker {
	if !p.ReturnContent {
		return p.runWithoutContent(ctx)
	}
	panic("not implemented")
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
