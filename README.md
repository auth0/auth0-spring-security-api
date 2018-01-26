# Auth0 Spring Security for API

[![Build][travis-ci-badge]][travis-ci-url]
[![MIT][mit-badge]][mit-url]
[![Maven][maven-badge]][maven-url]
[![Download][jcenter-badge]][jcenter-url]
[![codecov][codecov-badge]][codecov-url]

Spring Security integration with Auth0 to secure your API with Json Web Tokens (JWT)

> If you need to check the old version please check the branch [v0](https://github.com/auth0/auth0-spring-security-api/tree/v0)

## Download

Get Auth0 Spring Security API using Maven:

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>auth0-spring-security-api</artifactId>
    <version>1.0.0</version>
</dependency>
```

or Gradle:

```gradle
compile 'com.auth0:auth0-spring-security-api:1.0.0'
```

## Usage

Inside a `WebSecurityConfigurerAdapter` you can configure your api to only accept `RS256` signed JWTs

```java
@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        JwtWebSecurityConfigurer
                .forRS256("YOUR_API_AUDIENCE", "YOUR_API_ISSUER")
                .configure(http);
    }
}
```

or for `HS256` signed JWTs

```java
@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        JwtWebSecurityConfigurer
                .forHS256("YOUR_API_AUDIENCE", "YOUR_API_ISSUER", "YOUR_API_SECRET".getBytes())
                .configure(http);
    }
}
```


Then using Spring Security `HttpSecurity` you can specify which paths requires authentication

```java
    http.authorizeRequests()
        .antMatchers("/api/**").fullyAuthenticated();
```

and you can even specify that the JWT should have a single or several scopes

```java
    http.authorizeRequests()
        .antMatchers(HttpMethod.GET, "/api/users/**").hasAuthority("read:users");
```


`JwtWebSecurityConfigurer#configure(HttpSecurity)` also returns `HttpSecurity` so you can do the following:

```java
@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        JwtWebSecurityConfigurer
                .forRS256("YOUR_API_AUDIENCE", "YOUR_API_ISSUER")
                .configure(http)
                .authorizeRequests()
                        .antMatchers(HttpMethod.GET, "/api/users/**").hasAuthority("read:users");
    }
}
```
## Sample

Perhaps the easiest way to learn how to use this library (and quickly get started with a working app) is to study the [Auth0 Spring Security API Sample](https://github.com/auth0-samples/auth0-spring-security-api-sample/tree/v1) and its README.


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
[maven-badge]: https://img.shields.io/maven-central/v/com.auth0/auth0-spring-security-api.svg
[maven-url]: http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.auth0%22%20AND%20a%3A%22auth0-spring-security-api%22
[jcenter-badge]: https://api.bintray.com/packages/auth0/java/auth0-spring-security-api/images/download.svg
[jcenter-url]: https://bintray.com/auth0/java/auth0-spring-security-api/_latestVersion
[codecov-badge]: https://codecov.io/gh/auth0/auth0-spring-security-api/branch/master/graph/badge.svg
[codecov-url]: https://codecov.io/gh/auth0/auth0-spring-security-api
