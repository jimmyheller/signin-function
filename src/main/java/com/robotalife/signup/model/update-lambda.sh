mvn clean package
aws lambda update-function-code --function-name signup --zip-file fileb://target/robotalife-signup-shade.jar
