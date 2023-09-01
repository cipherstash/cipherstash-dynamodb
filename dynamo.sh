aws dynamodb create-table --endpoint-url http://localhost:8000 --table-name dict --attribute-definitions AttributeName=term,AttributeType=B --key-schema AttributeName=term,KeyType=HASH --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=

