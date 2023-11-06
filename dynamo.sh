aws dynamodb create-table \
    --table-name users \
    --attribute-definitions \
        AttributeName=pk,AttributeType=S \
        AttributeName=sk,AttributeType=S \
        AttributeName=term,AttributeType=S \
     --key-schema \
        AttributeName=pk,KeyType=HASH \
        AttributeName=sk,KeyType=RANGE \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
    --global-secondary-indexes "IndexName=TermIndex,KeySchema=[{AttributeName=term,KeyType=HASH}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5}" \
    --endpoint-url http://localhost:8000
