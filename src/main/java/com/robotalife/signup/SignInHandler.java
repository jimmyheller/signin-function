package com.robotalife.signup;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.google.gson.Gson;
import com.robotalife.signup.model.SignInException;
import com.robotalife.signup.model.SignInRequest;
import com.robotalife.signup.model.SignInResponse;
import com.robotalife.signup.model.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import software.amazon.awssdk.services.dynamodb.model.ResourceNotFoundException;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static java.time.temporal.ChronoUnit.DAYS;


public class SignInHandler implements RequestHandler<SignInRequest, APIGatewayProxyResponseEvent> {
    private static final String FUNCTION_NAME = "signin";
    private static final String BASIC_INFO_TABLE = "UserBasicInfo";
    private static final String USER_TOKEN_TABLE = "UserToken";

    @Override
    public APIGatewayProxyResponseEvent handleRequest(SignInRequest signInRequest, Context context) {
        context.getLogger().log(String.format("received request :[%s] for function:[%s]", signInRequest, FUNCTION_NAME));
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        HashMap<String, String> headers = new HashMap<>();
        response.setIsBase64Encoded(false);
        headers.put("Content-Type", "application/json");
        response.setHeaders(headers);
        //validate
        if (signInRequest == null) {
            context.getLogger().log(String.format("[BadRequest] signup request is null for function:[%s]", FUNCTION_NAME));
            throw new SignInException("[BadRequest] signup request can not be null");
        }
        String email = signInRequest.getEmail();
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        //generate token
        Region region = Region.EU_WEST_1;
        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
                .region(region)
                .build();
        User user = queryForEmail(dynamoDbClient, email, context);
        Map<String, String> payloadMap = new HashMap<>();
        if (!bCryptPasswordEncoder.matches(signInRequest.getPassword(), user.getPassword())) {
            context.getLogger().log(String.format("customer credentials are not correct: [%s]", email));
            throw new SignInException("[InternalServerError] the credentials are not correct.");
        }
        Instant instantTime = Instant.now().plus(30, DAYS);
        Date expiryDate = new Date(instantTime.getEpochSecond());
        //return response
        String token = generateJwtToken(payloadMap, context, expiryDate);
        saveIdItem(dynamoDbClient, user.getId().toString(), expiryDate.getTime(), context);
        SignInResponse signInResponse = SignInResponse.newInstance(user.getId(), user.getUsername(), token);
        String jsonResponse = new Gson().toJson(signInResponse);
        response.setStatusCode(200);
        response.setBody(jsonResponse);
        return response;

    }

    private void saveIdItem(DynamoDbClient ddb, String id, long expiryDate, Context context) {
        var itemValues = new HashMap<String, AttributeValue>();
        itemValues.put("Id", AttributeValue.builder().s(id).build());
        itemValues.put("TTL", AttributeValue.builder().n(String.valueOf(expiryDate)).build());
        PutItemRequest request = PutItemRequest.builder()
                .tableName(USER_TOKEN_TABLE)
                .item(itemValues)
                .build();
        try {
            ddb.putItem(request);
        } catch (ResourceNotFoundException e) {
            context.getLogger().log(String.format("Error: The Amazon DynamoDB table [%s] can't be found.", USER_TOKEN_TABLE));
            throw new SignInException(String.format("[InternalServerError] could not save user to [%s]" +
                    ", ResourceNotFoundException", USER_TOKEN_TABLE));
        } catch (DynamoDbException e) {
            context.getLogger().log(String.format("there was a dynamodb exception in putting item: [%s]", e.getMessage()));
            throw new SignInException(String.format("[InternalServerError] could not save user to [%s]",
                    BASIC_INFO_TABLE));
        }
    }

    private String generateJwtToken(Map<String, ?> payloadMap, Context context, Date expiryDate) {
        try {
            Algorithm algorithm = Algorithm.HMAC256("w3eH3lJxMCy3EJ69d9U#0rW");
            String token = JWT.create()
                    .withIssuer("robotalife")
                    .withPayload(payloadMap)
                    .withExpiresAt(expiryDate)
                    .sign(algorithm);
            return "Bearer " + token;
        } catch (JWTCreationException exception) {
            context.getLogger().log("[InternalServerError] could not generate jwt token");
            throw exception;
        }

    }

    public static User queryForEmail(DynamoDbClient dynamoDbClient,
                                     String email, Context context) {
        String partitionKeyName = "Email";
        // Set up an alias for the partition key name in case it's a reserved word
        HashMap<String, String> attrNameAlias = new HashMap<>();
        String partitionAlias = "#a";
        attrNameAlias.put(partitionAlias, partitionKeyName);

        // Set up mapping of the partition name with the value
        HashMap<String, AttributeValue> attrValues =
                new HashMap<>();

        attrValues.put(":" + partitionKeyName, AttributeValue.builder()
                .s(email)
                .build());

        String indexName = "Email-index";
        QueryRequest queryReq = QueryRequest.builder()
                .tableName(BASIC_INFO_TABLE)
                .indexName(indexName)
                .keyConditionExpression(partitionAlias + " = :" + partitionKeyName)
                .expressionAttributeNames(attrNameAlias)
                .expressionAttributeValues(attrValues)
                .build();

        try {
            QueryResponse response = dynamoDbClient.query(queryReq);
            if (response.count() == 1) {
                context.getLogger().log(String.format("email: [%s] exists in database", email));
                Map<String, AttributeValue> item = response.items().get(0);
                AttributeValue idValue = item.get("Id");
                AttributeValue emailValue = item.get("Email");
                AttributeValue usernameValue = item.get("Username");
                AttributeValue passwordValue = item.get("Password");
                User user = new User();
                user.setUsername(usernameValue.s());
                user.setEmail(emailValue.s());
                user.setPassword(passwordValue.s());
                user.setId(UUID.fromString(idValue.s()));
                return user;
            } else if (response.count() == 0) {
                context.getLogger().log(String.format("email:[%s] does not exist", email));
                throw new SignInException("[BadRequest] email does not exist.");
            } else {
                context.getLogger().log(String.format("[InternalServerError] There was a problem fetching the user [%s]", email));
            }
        } catch (DynamoDbException e) {
            context.getLogger().log(String.format("there was a problem in retrieving the email: [%s] and the message is [%s]"
                    , email, e.getMessage()));
            throw new SignInException("[InternalServerError] unhandled error in connecting to datasource.");
        }

        throw new SignInException("[InternalServerError] there is an handled situation in the code.");
    }


}
