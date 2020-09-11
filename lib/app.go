package checkawscloudwatchlogsinsights

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
	"github.com/jessevdk/go-flags"
	"github.com/mackerelio/checkers"
	"github.com/mackerelio/golib/pluginutil"
)

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

func (p *awsCWLogsInsightsPlugin) collectCount() (int, error) {
	queryID, err := p.startQuery()
	if err != nil {
		return 0, fmt.Errorf("failed to start query: %w", err)
	}
	// XXX implement proper wait & retry logic
	time.Sleep(10 * time.Second)
	res, _, err := p.getQueryResults(queryID)
	if err != nil {
		return 0, fmt.Errorf("failed to get query results: %w", err)
	}
	return extractCount(res)
}

// QueryLimit is limit for StartQuery
const QueryLimit = 100

// startQuery calls cloudwatchlogs.StartQuery()
// returns (queryId, error)
func (p *awsCWLogsInsightsPlugin) startQuery() (*string, error) {
	now := time.Now()
	endTime := aws.Int64(now.Unix())
	startTime := aws.Int64(now.Add(-1 * time.Minute).Unix())
	q, err := p.Service.StartQuery(&cloudwatchlogs.StartQueryInput{
		EndTime:       endTime,
		StartTime:     startTime,
		LogGroupNames: aws.StringSlice(p.LogGroupNames),
		QueryString:   aws.String(p.Query),
		Limit:         aws.Int64(QueryLimit),
	})
	if q == nil {
		return nil, err
	}
	return q.QueryId, err
}

// getQueryResults calls cloudwatchlogs.GetQueryResults()
// returns (results, finished, error)
// if finished is true, the query is not finished (scheduled or running).
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
	switch *(res.Status) {
	case cloudwatchlogs.QueryStatusComplete:
		finished = true
	case cloudwatchlogs.QueryStatusFailed:
		finished = true
	case cloudwatchlogs.QueryStatusCancelled:
		finished = true
	}

	// XXX Do we need Statistics?
	return res.Results, finished, err
}

// extractCount extracts value from given response.
// the response must have single record, and the record must have only one field and its content must be parsable as number.
func extractCount(res [][]*cloudwatchlogs.ResultField) (int, error) {
	if len(res) != 1 {
		return 0, fmt.Errorf("unexpected response size, expected %d but got %d", 1, len(res))
	}
	record := res[0]
	if len(record) != 1 || record[0] == nil || record[0].Value == nil {
		return 0, fmt.Errorf("Unexpected response, %#v", record)
	}
	cntStr := *(record[0].Value)
	cnt64, err := strconv.ParseInt(cntStr, 10, 32)
	if err != nil {
		return 0, err
	}
	return int(cnt64), nil
}

func (p *awsCWLogsInsightsPlugin) runWithoutContent() *checkers.Checker {
	count, err := p.collectCount()
	if err != nil {
		return checkers.Unknown(fmt.Sprint(err))
	}
	return p.checkCount(count)
}

func (p *awsCWLogsInsightsPlugin) run() *checkers.Checker {
	if !p.ReturnContent {
		return p.runWithoutContent()
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
		return checkers.Unknown(fmt.Sprint(err))
	}
	return p.run()
}
