aws dynamodb put-item \
    --table-name users \
    --endpoint-url http://localhost:8000 \
    --item '{"pk": {"S": "user:0431268792"}, "sk": {"S": "details"}, "term": {"S": "email:dan@coderdan.co"} }'

aws dynamodb put-item \
    --table-name users \
    --endpoint-url http://localhost:8000 \
    --item '{"pk": {"S": "user:0431268792"}, "sk": {"S": "dl"}, "term": {"S": "number:1234567"} }'

aws dynamodb put-item \
    --table-name users \
    --endpoint-url http://localhost:8000 \
    --item '{"pk": {"S": "user:0435280507"}, "sk": {"S": "details"}, "term": {"S": "email:lauren@laurenneko.com"} }'

aws dynamodb put-item \
    --table-name users \
    --endpoint-url http://localhost:8000 \
    --item '{"pk": {"S": "user:0435280507"}, "sk": {"S": "dl"}, "term": {"S": "number:678971"} }'

aws dynamodb put-item \
    --table-name users \
    --endpoint-url http://localhost:8000 \
    --item '{"pk": {"S": "user:0400123456"}, "sk": {"S": "details"}, "term": {"S": "email:lauren@laurenneko.com"} }'