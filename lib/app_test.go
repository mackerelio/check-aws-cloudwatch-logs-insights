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

func Test_awsCWLogsInsightsPlugin_getQueryResults(t *testing.T) {
	successRes := [][]*cloudwatchlogs.ResultField{
		{
			&cloudwatchlogs.ResultField{
				Field: aws.String("this-is-complete!"),
			},
		},
	}
	dummySvc := &mockAWSCloudWatchLogsClient{
		getQueryResultsOutputs: map[string]*cloudwatchlogs.GetQueryResultsOutput{
			"COMPLETED_ID": {
				Status:  aws.String(cloudwatchlogs.QueryStatusComplete),
				Results: successRes,
			},
			"CANCELLED_ID": {
				Status:  aws.String(cloudwatchlogs.QueryStatusCancelled),
				Results: nil,
			},
			"FAILED_ID": {
				Status:  aws.String(cloudwatchlogs.QueryStatusFailed),
				Results: nil,
			},
			"SCHEDULED_ID": {
				Status:  aws.String(cloudwatchlogs.QueryStatusScheduled),
				Results: nil,
			},
			"RUNNING_ID": {
				Status:  aws.String(cloudwatchlogs.QueryStatusRunning),
				Results: nil,
			},
		},
	}
	type args struct {
		queryID *string
	}
	tests := []struct {
		name    string
		args    args
		want    [][]*cloudwatchlogs.ResultField
		want1   bool
		wantErr bool
	}{
		{
			name: "will return results when completed",
			args: args{
				queryID: aws.String("COMPLETED_ID"),
			},
			want:    successRes,
			want1:   true,
			wantErr: false,
		},
		{
			name: "will return finished: true when failed",
			args: args{
				queryID: aws.String("FAILED_ID"),
			},
			want:    nil,
			want1:   true,
			wantErr: false,
		},
		{
			name: "will return finished: true when cancelled",
			args: args{
				queryID: aws.String("CANCELLED_ID"),
			},
			want:    nil,
			want1:   true,
			wantErr: false,
		},
		{
			name: "will return finished: false when scheduled",
			args: args{
				queryID: aws.String("SCHEDULED_ID"),
			},
			want:    nil,
			want1:   false,
			wantErr: false,
		},
		{
			name: "will return finished: false when running",
			args: args{
				queryID: aws.String("RUNNING_ID"),
			},
			want:    nil,
			want1:   false,
			wantErr: false,
		},
		{
			name: "will return err when API errors",
			args: args{
				queryID: aws.String("ERROR_ID"),
			},
			want:    nil,
			want1:   false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &awsCWLogsInsightsPlugin{
				Service: dummySvc,
			}
			got, got1, err := p.getQueryResults(tt.args.queryID)
			if (err != nil) != tt.wantErr {
				t.Errorf("awsCWLogsInsightsPlugin.getQueryResults() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("awsCWLogsInsightsPlugin.getQueryResults() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("awsCWLogsInsightsPlugin.getQueryResults() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
