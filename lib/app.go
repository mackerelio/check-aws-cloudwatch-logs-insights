package checkawscloudwatchlogsinsights

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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

	Filter        string `short:"f" long:"filter" required:"true" value-name:"FILTER" description:"Filter expression to use search logs via CloudWatch Logs Insights" unquote:"false"`
	WarningOver   int    `short:"w" long:"warning-over" value-name:"WARNING" description:"Trigger a warning if matched lines is over a number"`
	CriticalOver  int    `short:"c" long:"critical-over" value-name:"CRITICAL" description:"Trigger a critical if matched lines is over a number"`
	StateDir      string `short:"s" long:"state-dir" value-name:"DIR" description:"Dir to keep state files under" unquote:"false"`
	ReturnContent bool   `short:"r" long:"return" description:"Output earliest log found with given query"`
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
	if status != checkers.OK && p.ReturnContent {
		msg += "\n" + res.ReturnedMessage
	}
	return checkers.NewChecker(status, msg)
}

func (p *awsCWLogsInsightsPlugin) searchLogs(ctx context.Context) (*ParsedQueryResults, error) {
	endTime := time.Now()
	startTime := endTime.Add(-2 * time.Minute)
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
			stopQueryErr := p.stopQuery(queryID)
			if stopQueryErr != nil {
				return nil, fmt.Errorf("execution cancelled (%v) and failed to stop the runnig query: %w", err, stopQueryErr)
			}
			logger.Debugf("succeeded to cancel query")
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
					return nil, fmt.Errorf("failed to get query results: %w", err)
				}
				return res, err
			}
			logger.Debugf("Query not finished. Will wait a while...")
		}
	}
}

// fullQuery returns p.Filter with additional commands for searching Logs
func (p *awsCWLogsInsightsPlugin) fullQuery() string {
	fullQuery := p.Filter
	if p.ReturnContent {
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

func (p *awsCWLogsInsightsPlugin) run(ctx context.Context) *checkers.Checker {
	res, err := p.searchLogs(ctx)
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
