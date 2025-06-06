# cognito-m2m-rest-demo

A project to further my understanding of:

- OpenID Connect (OIDC) [Machine to Machine (M2M)](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-define-resource-servers.html#cognito-user-pools-define-resource-servers-about-m2m) auth flows
- [AWS Cognito](https://aws.amazon.com/pm/cognito/) managed service
- Implementing JSON Web Token (JWT) validation on a REST server, including caching and middleware

## Running Locally

1. Provision an AWS Cognito user pool with an app client which is enabled for client credentials grants (TODO: Terraform this)
2. Run the [Docker Compose](./docker-compose.yml) file to start the [Valkey](https://github.com/valkey-io/valkey) Docker container (Redis OSS replacement) as we use this for caching JWKS keys to avoid repeated calls over the internet when validating JWT's
3. Run the [rest-server-m2m](./rest-server-m2m) app to start the Go based REST server. This uses middleware to authZ the requests on the `/private` endpoint (`/public` is unprotected)
4. Generate a JWT using [go-client](./go-client). You will need the client ID and secret from the Cognito user pool app client
5. Use an HTTP client such as Postman and connect to the `localhost:8080/private` endpoint, passing the JWT using the `Authorization` header and [Bearer token](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Authentication#bearer)
6. Optionally run [tamper-jwt-token](./tamper-jwt-token) to attempt to send a tampered token (increase exp claim)—see later in this doc for more details

## Well-Known URIs

In AWS Cognito get the issuer URL from the overview page of the user pool.

```text
# The configuration of the issuer and includes the supported endpoint URL's (/oauth2/token etc)
https://<issuer>/.well-known/openid-configuration

# JSON Web Key Set (JWKS) - the public keys of the private keys which signed the JWT's
https://<issuer>/.well-known/jwks.json
```

## Verify the JWT Signature Validation is Working

To verify the app, protects against JWT tampering (the payload has changed):

1. Generate a valid JWT as normal using the [go-client](./go-client)
2. Pass the token to the [tamper-jwt-token](./tamper-jwt-token) app. This will extend the expiry time (exp claim) of the token and invalidate the signature
3. Call the rest-server-m2m REST server with the tampered token as an auth header. You should get an HTTP 401 response due to an invalid signature

## Todo

- Extend the HTTP client to also call the REST endpoints
- Extend docker-compose to also run the API server and the HTTP client
- Add Terraform config for Cognito
- Add unit tests for the middleware