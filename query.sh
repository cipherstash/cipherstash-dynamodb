aws dynamodb get-item \
    --table-name users \
    --endpoint-url http://localhost:8000 \
    --key '{"pk":{"S":"user:0431268792"}, "sk":{"S": "details"}}'

aws dynamodb query \
    --table-name users \
    --endpoint-url http://localhost:8000 \
    --index-name TermIndex \
    --key-condition-expression "term = :term" \
    --expression-attribute-values  '{":term":{"S":"email:lauren@laurenneko.com"}}'