package checkawscloudwatchlogsinsights

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
	"github.com/mackerelio/checkers"
	"github.com/stretchr/testify/mock"
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
	cloudwatchlogsiface.CloudWatchLogsAPI
	mock.Mock
}

func (c *mockAWSCloudWatchLogsClient) StartQuery(input *cloudwatchlogs.StartQueryInput) (*cloudwatchlogs.StartQueryOutput, error) {
	args := c.Called(input)
	res, _ := args.Get(0).(*cloudwatchlogs.StartQueryOutput)
	return res, args.Error(1)
}

func (c *mockAWSCloudWatchLogsClient) GetQueryResults(input *cloudwatchlogs.GetQueryResultsInput) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	args := c.Called(input)
	res, _ := args.Get(0).(*cloudwatchlogs.GetQueryResultsOutput)
	return res, args.Error(1)
}

func Test_parseResult(t *testing.T) {
	type args struct {
		out *cloudwatchlogs.GetQueryResultsOutput
	}
	simpleResult := [][]*cloudwatchlogs.ResultField{
		{
			&cloudwatchlogs.ResultField{
				Field: aws.String("@message"),
				Value: aws.String("msg-1"),
			},
		},
		{
			&cloudwatchlogs.ResultField{
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
					Status:  aws.String(cloudwatchlogs.QueryStatusComplete),
					Results: simpleResult,
					Statistics: &cloudwatchlogs.QueryStatistics{
						RecordsMatched: aws.Float64(25),
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
					Status:     aws.String(cloudwatchlogs.QueryStatusFailed),
					Results:    nil,
					Statistics: &cloudwatchlogs.QueryStatistics{},
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
					Status:  aws.String(cloudwatchlogs.QueryStatusCancelled),
					Results: nil,
					Statistics: &cloudwatchlogs.QueryStatistics{
						RecordsMatched: aws.Float64(25),
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
					Status:     aws.String(cloudwatchlogs.QueryStatusRunning),
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
					Status:  aws.String(cloudwatchlogs.QueryStatusComplete),
					Results: simpleResult,
					Statistics: &cloudwatchlogs.QueryStatistics{
						RecordsMatched: aws.Float64(25),
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
		LogGroupNames: aws.StringSlice([]string{"/log/foo", "/log/baz"}),
		QueryString:   aws.String("filter @message like /omg/"),
		Limit:         aws.Int64(10),
	}
	completeOutput := &cloudwatchlogs.GetQueryResultsOutput{
		Status: aws.String(cloudwatchlogs.QueryStatusComplete),
		Results: [][]*cloudwatchlogs.ResultField{
			{
				{
					Field: aws.String("@message"),
					Value: aws.String("omg something happend"),
				},
			},
		},
		Statistics: &cloudwatchlogs.QueryStatistics{
			RecordsMatched: aws.Float64(6),
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
				LogGroupNames: aws.StringSlice([]string{"/log/foo", "/log/baz"}),
				QueryString:   aws.String("filter @message like /omg/"),
				Limit:         aws.Int64(10),
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
				LogGroupNames: aws.StringSlice([]string{"/log/foo", "/log/baz"}),
				QueryString:   aws.String("filter @message like /omg/ | fields @message"),
				Limit:         aws.Int64(10),
			},
		},
		{
			name:   "GetQueryResults failed",
			fields: defaultFields,
			responses: []*cloudwatchlogs.GetQueryResultsOutput{
				{
					Status:     aws.String(cloudwatchlogs.QueryStatusFailed),
					Results:    [][]*cloudwatchlogs.ResultField{},
					Statistics: &cloudwatchlogs.QueryStatistics{},
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
					Status:     aws.String(cloudwatchlogs.QueryStatusRunning),
					Results:    [][]*cloudwatchlogs.ResultField{},
					Statistics: &cloudwatchlogs.QueryStatistics{},
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
					Status:     nil, // malformed
					Results:    [][]*cloudwatchlogs.ResultField{},
					Statistics: &cloudwatchlogs.QueryStatistics{},
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
			file, _ := ioutil.TempFile("", "check-aws-cloudwatch-logs-streams-test-searchLogs")
			if tt.logState == nil {
				os.Remove(file.Name())
			} else {
				b, _ := json.Marshal(tt.logState)
				ioutil.WriteFile(file.Name(), b, 0644)
			}
			file.Close()
			defer os.Remove(file.Name())

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
				StateFile: file.Name(),
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
			cnt, _ := ioutil.ReadFile(file.Name())
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
