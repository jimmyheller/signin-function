aws dynamodb create-table \
--attribute-definitions '[
  {"AttributeName": "Id", "AttributeType": "S"}
  ]' \
--table-name UserToken \
--key-schema '[{"AttributeName": "Id", "KeyType": "HASH"}]' \
--billing-mode PAY_PER_REQUEST \
--tags Key=app-name,Value=robotalife-app


aws dynamodb update-time-to-live --table-name UserToken --time-to-live-specification "Enabled=true, AttributeName=TTL"
