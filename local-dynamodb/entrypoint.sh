#!/bin/bash

set -euo pipefail

export AWS_ACCESS_KEY_ID=local
export AWS_SECRET_ACCESS_KEY=local
export AWS_DEFAULT_REGION=us-east-1
export DB_PATH=/data

run_dynamodb() {
	java -jar DynamoDBLocal.jar -sharedDb -dbPath "$DB_PATH"
}

create_tables() {
  aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name datasets \
    --attribute-definitions \
        AttributeName=id,AttributeType=S \
    --key-schema \
        AttributeName=id,KeyType=HASH \
    --provisioned-throughput \
        ReadCapacityUnits=5,WriteCapacityUnits=5

  aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name clients \
    --attribute-definitions \
        AttributeName=id,AttributeType=S \
    --key-schema \
        AttributeName=id,KeyType=HASH \
    --provisioned-throughput \
        ReadCapacityUnits=5,WriteCapacityUnits=5

  aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name tag-keys \
    --attribute-definitions \
        AttributeName=id,AttributeType=S \
    --key-schema \
        AttributeName=id,KeyType=HASH \
    --provisioned-throughput \
        ReadCapacityUnits=5,WriteCapacityUnits=5

  aws dynamodb create-table \
    --endpoint-url http://localhost:8000 \
    --table-name dataset-config \
    --attribute-definitions \
        AttributeName=id,AttributeType=S \
    --key-schema \
        AttributeName=id,KeyType=HASH \
    --provisioned-throughput \
        ReadCapacityUnits=5,WriteCapacityUnits=5
}

# Check if this is a new instance
NEW_DB=false
if [ ! -f "$DB_PATH/shared-local-instance.db" ]; then
  NEW_DB=true
fi

run_dynamodb &
PID="$!"

if [ "$NEW_DB" = true ]; then
  sleep 5
  create_tables
fi

wait $PID
exit $?
