package checkawscloudwatchlogsinsights

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
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
