mvn clean package
aws lambda update-function-code --function-name signin --zip-file fileb://target/robotalife-signin-shade.jar
