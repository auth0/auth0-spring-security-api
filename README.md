# Auth0 Spring Security Api

[![Build][travis-ci-badge]][travis-ci-url]
[![MIT][mit-badge]][mit-url]
[![Maven][maven-badge]][maven-url]

A modern Java Spring library that allows you to use Auth0 with Spring Security. Leverages Spring Boot dependencies.
Validates the JWT from Auth0 in every API call to assert authentication according to configuration.

## Download

Get Auth0 Spring Security API via Maven:

```xml
<dependency>
  <groupId>com.auth0</groupId>
  <artifactId>auth0-spring-security-api</artifactId>
  <version>0.0.1</version>
</dependency>
```

or Gradle:

```gradle
compile 'com.auth0:auth0-spring-security:0.0.1'
```

## Learn how to use it

Right now, the best way to learn how to use this library is to study the [Auth0 Spring Security API Sample](https://github.com/auth0-samples/auth0-spring-security-api-sample)
and the README for that sample. Our official documentation shall at the link below shall be fully updated shortly, together with Maven publication of the latest release. For
dev testing, just install locally with maven to get started right away.

[Please read this tutorial](https://docs.auth0.com/server-apis/java-spring-security-api) to learn how to use this SDK.

---

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, amont others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free account in Auth0

1. Go to [Auth0](http://developers.auth0.com) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

<!-- Vars -->

[travis-ci-badge]: https://travis-ci.org/auth0/auth0-spring-security.svg?branch=master
[travis-ci-url]: https://travis-ci.org/auth0/auth0-spring-security
[mit-badge]: http://img.shields.io/:license-mit-blue.svg?style=flat
[mit-url]: https://raw.githubusercontent.com/auth0/auth0-java/master/LICENSE
[maven-badge]: https://img.shields.io/maven-central/v/com.auth0/spring-security-auth0.svg
[maven-url]: http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.auth0%22%20AND%20a%3A%22spring-security-auth0%22