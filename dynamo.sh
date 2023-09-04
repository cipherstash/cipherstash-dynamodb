aws dynamodb create-table --endpoint-url http://localhost:8000 --table-name dict --attribute-definitions AttributeName=term_key,AttributeType=B --key-schema AttributeName=term_key,KeyType=HASH --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5

#aws dynamodb create-table \
#    --table-name postings \
#    --attribute-definitions \
#        AttributeName=term,AttributeType=B \
#        AttributeName=docid,AttributeType=S \
#    --key-schema AttributeName=term,KeyType=HASH \
#    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
#    --global-secondary-indexes "IndexName=DocIDIndex,KeySchema=[{AttributeName=docid,KeyType=HASH}],Projection={ProjectionType=ALL},ProvisionedThroughput={ReadCapacityUnits=5,WriteCapacityUnits=5}" \
#    --endpoint-url http://localhost:8000

aws dynamodb create-table \
    --table-name users \
    --attribute-definitions \
        AttributeName=id,AttributeType=S \
        AttributeName=term,AttributeType=B \
     --key-schema \
        AttributeName=id,KeyType=HASH \
        AttributeName=term,KeyType=RANGE \
    --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
    # Fixme: we still need a secondary index on term
    --endpoint-url http://localhost:8000
