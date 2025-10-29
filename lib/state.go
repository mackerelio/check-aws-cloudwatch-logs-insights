package checkawscloudwatchlogsinsights

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/natefinch/atomic"
)

type storeIface interface {
	Load(ctx context.Context) (*logState, error)
	Save(ctx context.Context, s *logState) error
}

type fileStore struct {
	StateFile string
}

func (p *fileStore) Load(_ context.Context) (*logState, error) {
	f, err := os.Open(p.StateFile)
	if err != nil && os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close() // nolint
	var s logState
	err = json.NewDecoder(f).Decode(&s)
	if err != nil {
		return nil, err
	}
	logger.Debugf("Loaded state from stateFile %s: %#v", p.StateFile, s)
	return &s, nil
}

func (p *fileStore) Save(_ context.Context, s *logState) error {
	logger.Debugf("Saving state to stateFile %s: %#v", p.StateFile, s)
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(s); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.StateFile), 0755); err != nil {
		return err
	}
	return atomic.WriteFile(p.StateFile, &buf)
}

type dynamodbStore struct {
	stateName string
	tableName string

	client dynamodbIface
}

type dynamodbIface interface {
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
}

func NewDynamodbStore(awsCfg aws.Config, tableName, stateName string) *dynamodbStore {
	return &dynamodbStore{
		stateName: stateName,
		tableName: tableName,
		client:    dynamodb.NewFromConfig(awsCfg),
	}
}

type dynamodbLogState struct {
	State     string `dynamodbav:"State"`
	UpdatedAt int64  `dynamodbav:"UpdatedAt"`

	*logState
}

func (d *dynamodbStore) Load(ctx context.Context) (*logState, error) {
	getInput := &dynamodb.GetItemInput{
		TableName: aws.String(d.tableName),
		Key: map[string]types.AttributeValue{
			"State": &types.AttributeValueMemberS{
				Value: d.stateName,
			},
		},
	}

	output, err := d.client.GetItem(ctx, getInput)
	if err != nil {
		return nil, err
	}

	if len(output.Item) == 0 {
		return nil, nil
	}

	var s logState
	err = attributevalue.UnmarshalMap(output.Item, &s)
	if err != nil {
		return nil, err
	}

	logger.Debugf("Loaded state from dynamodb %s: %#v", d.stateName, s)
	return &s, nil
}

var nowFunc = time.Now

func (d *dynamodbStore) Save(ctx context.Context, s *logState) error {
	logger.Debugf("Saving state to dynamodb %s: %#v", d.stateName, s)

	av, err := attributevalue.MarshalMap(dynamodbLogState{State: d.stateName, logState: s, UpdatedAt: nowFunc().Unix()})
	if err != nil {
		return err
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(d.tableName),
		Item:      av,
	}
	_, err = d.client.PutItem(ctx, input)
	return err
}
