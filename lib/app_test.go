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

func Test_awsCWLogsInsightsPlugin_buildChecker(t *testing.T) {
	type fields struct {
		Service   cloudwatchlogsiface.CloudWatchLogsAPI
		StateFile string
		logOpts   *logOpts
	}
	type args struct {
		res *ParsedQueryResults
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *checkers.Checker
	}{
		{
			name: "will return CRITICAL when count > CriticalOver",
			fields: fields{
				logOpts: &logOpts{
					CriticalOver: 4,
					WarningOver:  2,
				},
			},
			args: args{
				res: &ParsedQueryResults{
					MatchedCount: 5,
				},
			},
			want: checkers.Critical("5 > 4 messages"),
		},
		{
			name: "will return WARNING when CriticalOver > count > WarningOver",
			fields: fields{
				logOpts: &logOpts{
					CriticalOver: 4,
					WarningOver:  2,
				},
			},
			args: args{
				res: &ParsedQueryResults{
					MatchedCount: 3,
				},
			},
			want: checkers.Warning("3 > 2 messages"),
		},
		{
			name: "will return OK when WarningOver > count",
			fields: fields{
				logOpts: &logOpts{
					CriticalOver: 4,
					WarningOver:  2,
				},
			},
			args: args{
				res: &ParsedQueryResults{
					MatchedCount: 1,
				},
			},
			want: checkers.Ok("1 messages"),
		},
		{
			name: "will return WARNING when CriticalOver = count > WarningOver",
			fields: fields{
				logOpts: &logOpts{
					CriticalOver: 4,
					WarningOver:  2,
				},
			},
			args: args{
				res: &ParsedQueryResults{
					MatchedCount: 4,
				},
			},
			want: checkers.Warning("4 > 2 messages"),
		},
		{
			name: "will return OK when count = WarningOver",
			fields: fields{
				logOpts: &logOpts{
					CriticalOver: 4,
					WarningOver:  2,
				},
			},
			args: args{
				res: &ParsedQueryResults{
					MatchedCount: 2,
				},
			},
			want: checkers.Ok("2 messages"),
		},
		{
			name: "will include ReturnedMessage when ReturnMessage: true",
			fields: fields{
				logOpts: &logOpts{
					CriticalOver:  4,
					WarningOver:   2,
					ReturnMessage: true,
				},
			},
			args: args{
				res: &ParsedQueryResults{
					MatchedCount:    5,
					ReturnedMessage: "this-is-returned-message",
				},
			},
			want: checkers.Critical("5 > 4 messages\nthis-is-returned-message"),
		},
		{
			name: "will not include ReturnedMessage when ReturnMessage: false",
			fields: fields{
				logOpts: &logOpts{
					CriticalOver:  4,
					WarningOver:   2,
					ReturnMessage: false,
				},
			},
			args: args{
				res: &ParsedQueryResults{
					MatchedCount:    5,
					ReturnedMessage: "this-is-returned-message",
				},
			},
			want: checkers.Critical("5 > 4 messages"),
		}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &awsCWLogsInsightsPlugin{
				Service:   tt.fields.Service,
				StateFile: tt.fields.StateFile,
				logOpts:   tt.fields.logOpts,
			}
			if got := p.buildChecker(tt.args.res); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("awsCWLogsInsightsPlugin.buildChecker() = %v, want %v", got, tt.want)
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
	simpleResult := [][]*cloudwatchlogs.ResultField{
		{
			&cloudwatchlogs.ResultField{
				Field: aws.String("@message"),
				Value: aws.String("some-log"),
			},
		},
	}
	returnContentResult := [][]*cloudwatchlogs.ResultField{
		{
			&cloudwatchlogs.ResultField{
				Field: aws.String("earliest(@message)"),
				Value: aws.String("this-is-earliest-message"),
			},
		},
	}
	tests := []struct {
		name    string
		args    args
		wantRes *ParsedQueryResults
		wantErr bool
	}{
		{
			name: "complete",
			args: args{
				out: &cloudwatchlogs.GetQueryResultsOutput{
					Status:  aws.String(cloudwatchlogs.QueryStatusComplete),
					Results: simpleResult,
					Statistics: &cloudwatchlogs.QueryStatistics{
						RecordsMatched: aws.Float64(25),
					},
				},
			},
			wantRes: &ParsedQueryResults{
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
			wantRes: &ParsedQueryResults{
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
			wantRes: &ParsedQueryResults{
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
			wantRes: &ParsedQueryResults{
				Finished:     false, // running
				MatchedCount: 0,
			},
			wantErr: false,
		},
		{
			name: "with stats",
			args: args{
				out: &cloudwatchlogs.GetQueryResultsOutput{
					Status:  aws.String(cloudwatchlogs.QueryStatusComplete),
					Results: returnContentResult,
					Statistics: &cloudwatchlogs.QueryStatistics{
						RecordsMatched: aws.Float64(25),
					},
				},
			},
			wantRes: &ParsedQueryResults{
				Finished:        true, // complete
				MatchedCount:    25,
				ReturnedMessage: "this-is-earliest-message",
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
