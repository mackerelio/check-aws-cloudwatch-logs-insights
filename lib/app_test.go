package checkawscloudwatchlogsinsights

import (
	"errors"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
	"github.com/mackerelio/checkers"
)

func Test_awsCWLogsInsightsPlugin_checkCount(t *testing.T) {
	type args struct {
		count int
	}
	tests := []struct {
		name    string
		logOpts *logOpts
		args    args
		want    *checkers.Checker
	}{
		{
			name: "will return CRITICAL when count > CriticalOver",
			logOpts: &logOpts{
				CriticalOver: 4,
				WarningOver:  2,
			},
			args: args{5},
			want: checkers.Critical("5 > 4 messages"),
		},
		{
			name: "will return WARNING when CriticalOver > count > WarningOver",
			logOpts: &logOpts{
				CriticalOver: 4,
				WarningOver:  2,
			},
			args: args{3},
			want: checkers.Warning("3 > 2 messages"),
		},
		{
			name: "will return OK when WarningOver > count",
			logOpts: &logOpts{
				CriticalOver: 4,
				WarningOver:  2,
			},
			args: args{1},
			want: checkers.Ok("1 messages"),
		},
		{
			name: "will return WARNING when CriticalOver = count > WarningOver",
			logOpts: &logOpts{
				CriticalOver: 4,
				WarningOver:  2,
			},
			args: args{4},
			want: checkers.Warning("4 > 2 messages"),
		},
		{
			name: "will return OK when count = WarningOver",
			logOpts: &logOpts{
				CriticalOver: 4,
				WarningOver:  2,
			},
			args: args{2},
			want: checkers.Ok("2 messages"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &awsCWLogsInsightsPlugin{
				logOpts: tt.logOpts,
			}
			if got := p.checkCount(tt.args.count); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("awsCWLogsInsightsPlugin.checkCount() = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockAWSCloudWatchLogsClient struct {
	cloudwatchlogsiface.CloudWatchLogsAPI
	getQueryResultsOutputs map[string]*cloudwatchlogs.GetQueryResultsOutput
}

func (c *mockAWSCloudWatchLogsClient) GetQueryResults(input *cloudwatchlogs.GetQueryResultsInput) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	if input.QueryId == nil {
		return c.getQueryResultsOutputs[""], nil
	}
	if out, ok := c.getQueryResultsOutputs[*input.QueryId]; ok {
		return out, nil
	}
	return nil, errors.New("invalid QueryId")
}

func Test_parseResult(t *testing.T) {
	type args struct {
		out *cloudwatchlogs.GetQueryResultsOutput
	}
	successResult := [][]*cloudwatchlogs.ResultField{
		{
			&cloudwatchlogs.ResultField{
				Field: aws.String("@message"),
				Value: aws.String("some-log"),
			},
		},
	}
	tests := []struct {
		name    string
		args    args
		wantRes *ParsedQueryResult
		wantErr bool
	}{
		{
			name: "complete",
			args: args{
				out: &cloudwatchlogs.GetQueryResultsOutput{
					Status:  aws.String(cloudwatchlogs.QueryStatusComplete),
					Results: successResult,
					Statistics: &cloudwatchlogs.QueryStatistics{
						RecordsMatched: aws.Float64(25),
					},
				},
			},
			wantRes: &ParsedQueryResult{
				Finished:     true, // complete
				MatchedCount: 25,
			},
			wantErr: false,
		},
		{
			name: "failed",
			args: args{
				out: &cloudwatchlogs.GetQueryResultsOutput{
					Status:     aws.String(cloudwatchlogs.QueryStatusFailed),
					Results:    nil,
					Statistics: &cloudwatchlogs.QueryStatistics{},
				},
			},
			wantRes: &ParsedQueryResult{
				Finished:     true, // failed
				MatchedCount: 0,
			},
			wantErr: false,
		},
		{
			name: "cancelled",
			args: args{
				out: &cloudwatchlogs.GetQueryResultsOutput{
					Status:  aws.String(cloudwatchlogs.QueryStatusCancelled),
					Results: nil,
					Statistics: &cloudwatchlogs.QueryStatistics{
						RecordsMatched: aws.Float64(25),
					},
				},
			},
			wantRes: &ParsedQueryResult{
				Finished:     true, // cancelled
				MatchedCount: 25,
			},
			wantErr: false,
		},
		{
			name: "running",
			args: args{
				out: &cloudwatchlogs.GetQueryResultsOutput{
					Status:     aws.String(cloudwatchlogs.QueryStatusRunning),
					Results:    nil,
					Statistics: nil,
				},
			},
			wantRes: &ParsedQueryResult{
				Finished:     false, // running
				MatchedCount: 0,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRes, err := parseResult(tt.args.out)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseResult() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotRes, tt.wantRes) {
				t.Errorf("parseResult() = %v, want %v", gotRes, tt.wantRes)
			}
		})
	}
}
