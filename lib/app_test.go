package checkawscloudwatchlogsinsights

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/mackerelio/checkers"
	"github.com/stretchr/testify/mock"
)

func Test_awsCWLogsInsightsPlugin_buildChecker(t *testing.T) {
	type fields struct {
		Service   cwIface
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
					MatchedCount:     5,
					ReturnedMessages: []string{"this-is-returned-message", "this-is-also-returned-message"},
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
					MatchedCount:     3,
					ReturnedMessages: []string{"this-is-returned-message", "this-is-also-returned-message"},
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
					MatchedCount:     1,
					ReturnedMessages: []string{"this-is-returned-message"},
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
					MatchedCount:     4,
					ReturnedMessages: []string{"this-is-returned-message", "this-is-also-returned-message"},
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
					MatchedCount:     2,
					ReturnedMessages: []string{"this-is-returned-message", "this-is-also-returned-message"},
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
					MatchedCount:     5,
					ReturnedMessages: []string{"this-is-returned-message", "this-is-also-returned-message"},
				},
			},
			want: checkers.Critical("5 > 4 messages\nthis-is-returned-message\nthis-is-also-returned-message"),
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
					MatchedCount:     5,
					ReturnedMessages: []string{"this-is-returned-message", "this-is-also-returned-message"},
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
	cwIface
	mock.Mock
}

func (c *mockAWSCloudWatchLogsClient) StartQuery(_ context.Context, input *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	args := c.Called(input)
	res, _ := args.Get(0).(*cloudwatchlogs.StartQueryOutput)
	return res, args.Error(1)
}

func (c *mockAWSCloudWatchLogsClient) GetQueryResults(_ context.Context, input *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	args := c.Called(input)
	res, _ := args.Get(0).(*cloudwatchlogs.GetQueryResultsOutput)
	return res, args.Error(1)
}

func Test_parseResult(t *testing.T) {
	type args struct {
		out *cloudwatchlogs.GetQueryResultsOutput
	}
	simpleResult := [][]types.ResultField{
		{
			types.ResultField{
				Field: aws.String("@message"),
				Value: aws.String("msg-1"),
			},
		},
		{
			types.ResultField{
				Field: aws.String("@message"),
				Value: aws.String("msg-2"),
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
					Status:  types.QueryStatusComplete,
					Results: simpleResult,
					Statistics: &types.QueryStatistics{
						RecordsMatched: 25,
					},
				},
			},
			wantRes: &ParsedQueryResults{
				Finished:         true, // complete
				MatchedCount:     25,
				ReturnedMessages: []string{"msg-1", "msg-2"},
			},
			wantErr: false,
		},
		{
			name: "failed",
			args: args{
				out: &cloudwatchlogs.GetQueryResultsOutput{
					Status:     types.QueryStatusFailed,
					Results:    nil,
					Statistics: &types.QueryStatistics{},
				},
			},
			wantRes: &ParsedQueryResults{
				Finished:         true, // failed
				FailureReason:    "query was finished with `Failed` status",
				MatchedCount:     0,
				ReturnedMessages: []string{},
			},
			wantErr: false,
		},
		{
			name: "cancelled",
			args: args{
				out: &cloudwatchlogs.GetQueryResultsOutput{
					Status:  types.QueryStatusCancelled,
					Results: nil,
					Statistics: &types.QueryStatistics{
						RecordsMatched: 25,
					},
				},
			},
			wantRes: &ParsedQueryResults{
				Finished:         true, // cancelled
				FailureReason:    "query was finished with `Cancelled` status",
				MatchedCount:     25,
				ReturnedMessages: []string{},
			},
			wantErr: false,
		},
		{
			name: "running",
			args: args{
				out: &cloudwatchlogs.GetQueryResultsOutput{
					Status:     types.QueryStatusRunning,
					Results:    nil,
					Statistics: nil,
				},
			},
			wantRes: &ParsedQueryResults{
				Finished:         false, // running
				MatchedCount:     0,
				ReturnedMessages: []string{},
			},
			wantErr: false,
		},
		{
			name: "with stats",
			args: args{
				out: &cloudwatchlogs.GetQueryResultsOutput{
					Status:  types.QueryStatusComplete,
					Results: simpleResult,
					Statistics: &types.QueryStatistics{
						RecordsMatched: 25,
					},
				},
			},
			wantRes: &ParsedQueryResults{
				Finished:         true, // complete
				MatchedCount:     25,
				ReturnedMessages: []string{"msg-1", "msg-2"},
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

func Test_awsCWLogsInsightsPlugin_searchLogs(t *testing.T) {
	now := time.Now()
	type fields struct {
		logOpts *logOpts
	}
	defaultFields := fields{
		logOpts: &logOpts{
			LogGroupNames: []string{"/log/foo", "/log/baz"},
			Filter:        "filter @message like /omg/",
		},
	}
	defaultWantInput := &cloudwatchlogs.StartQueryInput{
		StartTime:     aws.Int64(now.Add(-6 * time.Minute).Unix()),
		EndTime:       aws.Int64(now.Add(-5 * time.Minute).Unix()),
		LogGroupNames: []string{"/log/foo", "/log/baz"},
		QueryString:   aws.String("filter @message like /omg/"),
		Limit:         aws.Int32(10),
	}
	completeOutput := &cloudwatchlogs.GetQueryResultsOutput{
		Status: types.QueryStatusComplete,
		Results: [][]types.ResultField{
			{
				{
					Field: aws.String("@message"),
					Value: aws.String("omg something happend"),
				},
			},
		},
		Statistics: &types.QueryStatistics{
			RecordsMatched: 6,
		},
	}
	tests := []struct {
		name             string
		fields           fields
		responses        []*cloudwatchlogs.GetQueryResultsOutput
		logState         *logState // when nil, remove stateFile
		want             *ParsedQueryResults
		wantErr          bool
		wantNextLogState *logState
		wantInput        *cloudwatchlogs.StartQueryInput
	}{
		{
			name:      "without state file",
			fields:    defaultFields,
			responses: []*cloudwatchlogs.GetQueryResultsOutput{completeOutput},
			logState:  nil,
			want: &ParsedQueryResults{
				Finished:         true,
				MatchedCount:     6,
				ReturnedMessages: []string{"omg something happend"},
			},
			wantErr: false,
			wantNextLogState: &logState{
				EndTime: now.Add(-5 * time.Minute).Unix(),
			},
			wantInput: defaultWantInput,
		},
		{
			name:      "with state file",
			fields:    defaultFields,
			responses: []*cloudwatchlogs.GetQueryResultsOutput{completeOutput},
			logState: &logState{
				EndTime: now.Add(-42 * time.Minute).Unix(),
			},
			want: &ParsedQueryResults{
				Finished:         true,
				MatchedCount:     6,
				ReturnedMessages: []string{"omg something happend"},
			},
			wantErr: false,
			wantNextLogState: &logState{
				EndTime: now.Add(-5 * time.Minute).Unix(),
			},
			wantInput: &cloudwatchlogs.StartQueryInput{
				StartTime:     aws.Int64(now.Add(-42 * time.Minute).Unix()),
				EndTime:       aws.Int64(now.Add(-5 * time.Minute).Unix()),
				LogGroupNames: []string{"/log/foo", "/log/baz"},
				QueryString:   aws.String("filter @message like /omg/"),
				Limit:         aws.Int32(10),
			},
		},
		{
			name:      "too old stateFile",
			fields:    defaultFields,
			responses: []*cloudwatchlogs.GetQueryResultsOutput{completeOutput},
			logState: &logState{
				EndTime: now.Add(-365 * time.Minute).Unix(), // too old
			},
			want: &ParsedQueryResults{
				Finished:         true,
				MatchedCount:     6,
				ReturnedMessages: []string{"omg something happend"},
			},
			wantErr: false,
			wantNextLogState: &logState{
				EndTime: now.Add(-5 * time.Minute).Unix(),
			},
			wantInput: defaultWantInput, // QueryStartedAt is ignored
		}, {
			name: "with ReturnMessage: true",
			fields: fields{
				logOpts: &logOpts{
					LogGroupNames: []string{"/log/foo", "/log/baz"},
					Filter:        "filter @message like /omg/",
					ReturnMessage: true,
				},
			},
			responses: []*cloudwatchlogs.GetQueryResultsOutput{completeOutput},
			logState:  nil,
			want: &ParsedQueryResults{
				Finished:         true,
				MatchedCount:     6,
				ReturnedMessages: []string{"omg something happend"},
			},
			wantErr: false,
			wantNextLogState: &logState{
				EndTime: now.Add(-5 * time.Minute).Unix(),
			},
			wantInput: &cloudwatchlogs.StartQueryInput{
				StartTime:     aws.Int64(now.Add(-6 * time.Minute).Unix()),
				EndTime:       aws.Int64(now.Add(-5 * time.Minute).Unix()),
				LogGroupNames: []string{"/log/foo", "/log/baz"},
				QueryString:   aws.String("filter @message like /omg/ | fields @message"),
				Limit:         aws.Int32(10),
			},
		},
		{
			name:   "GetQueryResults failed",
			fields: defaultFields,
			responses: []*cloudwatchlogs.GetQueryResultsOutput{
				{
					Status:     types.QueryStatusFailed,
					Results:    [][]types.ResultField{},
					Statistics: &types.QueryStatistics{},
				},
			},
			logState: nil,
			want:     nil,
			wantErr:  true,
			wantNextLogState: &logState{
				EndTime: now.Add(-5 * time.Minute).Unix(),
			},
			wantInput: defaultWantInput,
		},
		{
			name:   "GetQueryResults running => completed",
			fields: defaultFields,
			responses: []*cloudwatchlogs.GetQueryResultsOutput{
				{
					Status:     types.QueryStatusRunning,
					Results:    [][]types.ResultField{},
					Statistics: &types.QueryStatistics{},
				},
				completeOutput,
			},
			logState: nil,
			want: &ParsedQueryResults{
				Finished:         true,
				MatchedCount:     6,
				ReturnedMessages: []string{"omg something happend"},
			},
			wantErr: false,
			wantNextLogState: &logState{
				EndTime: now.Add(-5 * time.Minute).Unix(),
			},
			wantInput: defaultWantInput,
		},
		{
			name:   "GetQueryResults API error => completed",
			fields: defaultFields,
			responses: []*cloudwatchlogs.GetQueryResultsOutput{
				nil,
				completeOutput,
			},
			logState: nil,
			want: &ParsedQueryResults{
				Finished:         true,
				MatchedCount:     6,
				ReturnedMessages: []string{"omg something happend"},
			},
			wantErr: false,
			wantNextLogState: &logState{
				EndTime: now.Add(-5 * time.Minute).Unix(),
			},
			wantInput: defaultWantInput,
		},
		{
			name:   "GetQueryResults malformed response => completed",
			fields: defaultFields,
			responses: []*cloudwatchlogs.GetQueryResultsOutput{
				{
					Status:     types.QueryStatusUnknown, // malformed
					Results:    [][]types.ResultField{},
					Statistics: &types.QueryStatistics{},
				},
				completeOutput,
			},
			logState: nil,
			want: &ParsedQueryResults{
				Finished:         true,
				MatchedCount:     6,
				ReturnedMessages: []string{"omg something happend"},
			},
			wantErr: false,
			wantNextLogState: &logState{
				EndTime: now.Add(-5 * time.Minute).Unix(),
			},
			wantInput: defaultWantInput,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// prepare state
			filename := filepath.Join(t.TempDir(), "check-aws-cloudwatch-logs-streams-test-searchLogs")
			if tt.logState == nil {
				os.Remove(filename)
			} else {
				b, _ := json.Marshal(tt.logState)
				os.WriteFile(filename, b, 0644) // nolint
			}

			svc := &mockAWSCloudWatchLogsClient{}
			svc.On("StartQuery", tt.wantInput).Return(&cloudwatchlogs.StartQueryOutput{
				QueryId: aws.String("DUMMY-QUERY-ID"),
			}, nil)
			for _, r := range tt.responses {
				call := svc.On("GetQueryResults", mock.AnythingOfType("*cloudwatchlogs.GetQueryResultsInput"))
				if r != nil {
					call.Return(r, nil).Once()
				} else {
					// return some error instead
					call.Return(nil, errors.New("failed to get")).Once()
				}
			}
			p := &awsCWLogsInsightsPlugin{
				Service:   svc,
				StateFile: filename,
				logOpts:   tt.fields.logOpts,
			}
			got, err := p.searchLogs(context.TODO(), now, time.Millisecond)
			if (err != nil) != tt.wantErr {
				t.Errorf("awsCWLogsInsightsPlugin.searchLogs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("awsCWLogsInsightsPlugin.searchLogs() = %v, want %v", got, tt.want)
			}
			svc.AssertExpectations(t)

			// test whether stateFile is updated
			cnt, _ := os.ReadFile(filename)
			var s logState
			err = json.NewDecoder(bytes.NewReader(cnt)).Decode(&s)
			if err != nil {
				t.Error("failed to load saved stateFile")
			}
			if !reflect.DeepEqual(&s, tt.wantNextLogState) {
				t.Errorf("logState %v, want %v", s, tt.wantNextLogState)
			}

		})
	}
}
