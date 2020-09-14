package checkawscloudwatchlogsinsights

import (
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
			name: "errors when res has multiple lines",
			args: args{
				res: [][]*cloudwatchlogs.ResultField{
					{
						&cloudwatchlogs.ResultField{
							Value: aws.String("2"),
						},
					},
					{
						&cloudwatchlogs.ResultField{
							Value: aws.String("3"),
						},
					},
				},
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "errors when res has multiple fields",
			args: args{
				res: [][]*cloudwatchlogs.ResultField{
					{
						&cloudwatchlogs.ResultField{
							Value: aws.String("2"),
						},
						&cloudwatchlogs.ResultField{
							Value: aws.String("3"),
						},
					},
				},
			},
			want:    0,
			wantErr: true,
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
	type fields struct {
		Service   cloudwatchlogsiface.CloudWatchLogsAPI
		StateFile string
		logOpts   *logOpts
	}
	type args struct {
		count int
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
			args: args{5},
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
			args: args{3},
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
			args: args{1},
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
			args: args{4},
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
			args: args{2},
			want: checkers.Ok("2 messages"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &awsCWLogsInsightsPlugin{
				Service:   tt.fields.Service,
				StateFile: tt.fields.StateFile,
				logOpts:   tt.fields.logOpts,
			}
			if got := p.checkCount(tt.args.count); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("awsCWLogsInsightsPlugin.checkCount() = %v, want %v", got, tt.want)
			}
		})
	}
}
