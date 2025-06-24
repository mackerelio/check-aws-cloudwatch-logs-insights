package checkawscloudwatchlogsinsights

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type mockDynamodb struct {
	State   string
	endTime string

	params *dynamodb.PutItemInput
}

func (m *mockDynamodb) GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	return &dynamodb.GetItemOutput{
		Item: map[string]types.AttributeValue{
			"State":   &types.AttributeValueMemberS{Value: m.State},
			"endTime": &types.AttributeValueMemberN{Value: m.endTime},
		},
	}, nil
}
func (m *mockDynamodb) PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	m.params = params
	return nil, nil
}

func TestDynamodbLogState(t *testing.T) {
	stateName := "stateName"
	tableName := "tableName"

	client := &mockDynamodb{State: stateName, endTime: "123"}

	store := &dynamodbStore{
		stateName: stateName,
		tableName: tableName,
		client:    client,
	}

	t.Run("Load", func(t *testing.T) {
		actual, err := store.Load(context.Background())
		if err != nil {
			t.Error(err)
		}

		if actual.EndTime != 123 {
			t.Error("invalid EndTime")
		}
	})

	t.Run("Save", func(t *testing.T) {
		err := store.Save(context.Background(), &logState{EndTime: 234})
		if err != nil {
			t.Error(err)
		}

		expected := &dynamodb.PutItemInput{
			Item: map[string]types.AttributeValue{
				"State":   &types.AttributeValueMemberS{Value: stateName},
				"endTime": &types.AttributeValueMemberN{Value: "234"},
			},
			TableName: &tableName,
		}

		if !reflect.DeepEqual(client.params, expected) {
			t.Error("invalid params")
		}
	})

}
