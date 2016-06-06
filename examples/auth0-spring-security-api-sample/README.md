### Spring Boot / Auth0 JWT API

Demonstrates using Auth0 with Spring Boot and Spring Security to create public and secured Controller / RestController endpoints
- this library would be typically used with an API server (headless).

This example relies upon `Spring Boot`.

Benefits of Spring Boot, in particular for traditional server-side web application / microservices architectures:

**Automatic configuration** - Spring Boot can automatically provide configuration for application functionality common to many Spring applications.

**Starter dependencies** - Tell Spring Boot what kind of functionality you need, and it will ensure that the libraries needed are added to the build.

**Command-line interface** - Optional feature of Spring Boot lets you write complete applications with just application code, but no need for a traditional
 project build.

**The Actuator** - Gives you insight into what's going on inside of a running Spring Boot application.

Useful quick start reference to getting started with [Spring Boot](https://docs.spring.io/spring-boot/docs/current/reference/html/getting-started-first-application.html)

### Prerequisites

In order to run this example you will need to have Maven installed. You can install Maven with [brew](http://brew.sh/):

```sh
brew install maven
```

Check that your maven version is 3.0.x or above:

```sh
mvn -v
```

#### Instructions to get started.

Create an application in via [Auth0 Dashboard](https://auth0.com/)

Add your `auth0_domain`, `client_id`, and `client_secret` to src/main/resources/auth0.properties of this project of this project

### Build and Run

In order to build and run the project you must execute:

```sh
mvn clean package
```

```sh
java -jar target/auth0-spring-security-api-sample-0.0.1-SNAPSHOT.jar
```

Alternatively, use:

```sh
mvn spring-boot:run
```

### Test the API

To run a request against the exposed API endpoints, simply make GET or POST requests as follows (using any http client you choose):


#### Public endpoint:

```
curl -X GET -H "Content-Type: application/json" -H "Cache-Control: no-cache" "http://localhost:3001/ping"
```

#### Secured endpoints:

```
curl -X GET -H "Authorization: Bearer {{YOUR JWT TOKEN}}" -H "Content-Type: application/json" -H "Cache-Control: no-cache" "http://localhost:3001/secured/ping"
```

or

```
curl -X GET -H "Authorization: Bearer {{YOUR JWT TOKEN}}" -H "Content-Type: application/json" -H "Cache-Control: no-cache" "http://localhost:3001/secured/getUsername"
```

or

```
curl -X POST -H "Authorization: Bearer {{YOUR JWT TOKEN}}" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -d '{"hello":"world"}' "http://localhost:3001/secured/post"
```

There is also a [postman](https://www.getpostman.com) collection (postman/auth0-spring-boot-api-example.postman_collection.json) published in case
you use postman for your API testing. Again, replace {{JWT_TOKEN}} with your token (or use Postman's `manage environments` feature to map JWT_TOKEN key
to your jwt token string).

Key Point: Remember to include the `Authorization: Bearer {{YOUR JWT TOKEN}}"` header. You can generate a JWT perhaps easiest by downloading
a web client sample from the Auth0 Dashboard for the same application you defined above, and then by logging using that App and retrieving the
generated JWT token that way.

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, amont others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free account in Auth0

1. Go to [Auth0](https://auth0.com) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt) file for more info.


