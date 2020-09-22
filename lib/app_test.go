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

func Test_extractCount(t *testing.T) {
	type args struct {
		res [][]*cloudwatchlogs.ResultField
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{
			name: "can extract count from expected format",
			args: args{
				res: [][]*cloudwatchlogs.ResultField{
					{
						&cloudwatchlogs.ResultField{
							Value: aws.String("2"),
						},
					},
				},
			},
			want:    2,
			wantErr: false,
		},
		{
			name: "errors when res has a empty line",
			args: args{
				res: [][]*cloudwatchlogs.ResultField{
					{},
				},
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "errors when res has a empty field",
			args: args{
				res: [][]*cloudwatchlogs.ResultField{
					{
						&cloudwatchlogs.ResultField{},
					},
				},
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "errors when res is nil",
			args: args{
				res: nil,
			},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractCount(tt.args.res)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractCount() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractCount() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
		res *cloudwatchlogs.GetQueryResultsOutput
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
		want    int
		want1   bool
		wantErr bool
	}{
		{
			name: "complete",
			args: args{
				res: &cloudwatchlogs.GetQueryResultsOutput{
					Status:  aws.String(cloudwatchlogs.QueryStatusComplete),
					Results: successResult,
					Statistics: &cloudwatchlogs.QueryStatistics{
						RecordsMatched: aws.Float64(25),
					},
				},
			},
			want:    25,
			want1:   true, // complete
			wantErr: false,
		},
		{
			name: "failed",
			args: args{
				res: &cloudwatchlogs.GetQueryResultsOutput{
					Status:     aws.String(cloudwatchlogs.QueryStatusFailed),
					Results:    nil,
					Statistics: &cloudwatchlogs.QueryStatistics{},
				},
			},
			want:    0,
			want1:   true, // failed
			wantErr: false,
		},
		{
			name: "cancelled",
			args: args{
				res: &cloudwatchlogs.GetQueryResultsOutput{
					Status:  aws.String(cloudwatchlogs.QueryStatusCancelled),
					Results: nil,
					Statistics: &cloudwatchlogs.QueryStatistics{
						RecordsMatched: aws.Float64(25),
					},
				},
			},
			want:    25,
			want1:   true, // cancelled
			wantErr: false,
		},
		{
			name: "running",
			args: args{
				res: &cloudwatchlogs.GetQueryResultsOutput{
					Status:     aws.String(cloudwatchlogs.QueryStatusRunning),
					Results:    nil,
					Statistics: nil,
				},
			},
			want:    0,
			want1:   false, // running
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := parseResult(tt.args.res)
			if (err != nil) != tt.wantErr {
				t.Errorf("awsCWLogsInsightsPlugin.parseResult() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("awsCWLogsInsightsPlugin.parseResult() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("awsCWLogsInsightsPlugin.parseResult() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
