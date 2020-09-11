package checkawscloudwatchlogsinsights

import (
	"fmt"
	"os"
	"path/filepath"

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
	return 3, nil
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
