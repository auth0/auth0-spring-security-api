# Auth0 Spring Security Api

[![Build][travis-ci-badge]][travis-ci-url]
[![MIT][mit-badge]][mit-url]
[![Maven][maven-badge]][maven-url]

A modern Java Spring library that allows you to use Auth0 with Spring Security. Leverages Spring Boot dependencies.
Validates the JWT from Auth0 in every API call to assert authentication according to configuration.

This library is suitable for headless APIs and SPA (single page application) backend end server scenarios.

This library provides you your application with easy access to able to:

 1. Configure and run Java based Spring API server with Auth0 and Spring Security
 2. Use 100% Java Configuration (Annotations)
 3. Secure one or more URL endpoints with Role / Authority based permissions (ROLE_USER, ROLE_ADMIN etc)
 4. Secure Java Services using method level security annotations for role based access control

If you are planning to use this in conjunction with a Single Page Application (SPA), then there are a couple of different
architectures you might consider:

1). You could either co-locate the SPA inside the same Spring Boot app from which you use this library
(drop your SPA code under /src/main/resources as you would for any Spring Boot application - and then the
SPA talks directly to its web-server (Spring Boot) using JWT authorization on all requests to secured endpoints
as defined by your AppConfig ( just augment here ).

2). You could have a separate server process that acts as the web-server for your SPA app (Node.js / Express.js is a
popular choice here - doesn't have to be Java), and then use the Auth0 / Java Spring Boot API running as a
separate web server to expose API endpoints as required for server-side functions of our SPA application.
This is a popular architecture style, and Cross Origin support is baked into the API config for that purpose.


## Download

Get Auth0 Spring Security API via Maven:

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>auth0-spring-security-api</artifactId>
    <version>0.2.0</version>
</dependency>
```

or Gradle:

```gradle
compile 'com.auth0:auth0-spring-security-api:0.2.0'
```

## Learn how to use it

[Please read this tutorial](https://auth0.com/docs/quickstart/backend/java-spring-security/) to learn how to use this SDK.

Perhaps the best way to learn how to use this library is to study the [Auth0 Spring Security API Sample](https://github.com/auth0-samples/auth0-spring-security-api-sample)
source code and its README file. 

Information on configuration and extension points is provided below. 

Note: If you are planning to use / are using the [Auth0 Resource Server (API Auth)](https://auth0.com/docs/api-auth/using-the-auth0-dashboard) as part of the
[API Authentication and Authorization](https://auth0.com/docs/api-auth) flows, then please study the
[Auth0 Spring Security API Resource Server Sample](https://github.com/auth0-samples/auth0-spring-security-api-resource-server-sample) and the README for that sample.
The Resource Server sample also depends almost exclusively on this library - and behaves almost identically with the exception of configuration related changes.

---

## Default Configuration

Here is a listing of each of the configuration options and their meaing. If you are writing your Client application
using `Spring Boot` for example, this is as simple as dropping the following file (`auth0.properties`) into the `src/main/resources`
directory alongside `application.properties`.

Here is an example of a populated `auth0.properties` file:

```
auth0.domain:arcseldon.auth0.com
auth0.issuer: https://arcseldon.auth0.com/
auth0.clientId: eTQbNn3qxypLq2Lc1qQEThYL6R7M7MDh
auth0.clientSecret: Z3xxxxxxCB6ZMaJLOcoS94xxxxbyzGWlTvwR44fkxxxxxMCbiVtgBFFA
auth0.securedRoute:/api/v1/**
auth0.base64EncodedSecret: true
auth0.authorityStrategy: ROLES
auth0.defaultAuth0ApiSecurityEnabled: false
auth0.signingAlgorithm: HS256
auth0.publicKeyPath:
```

Please take a look at the sample that accompanies this library for an easy seed project to see this working.

Here is a breakdown of what each attribute means:

`auth0.domain` - This is your auth0 domain (tenant you have created when registering with auth0 - account name)

`auth0.issuer` - This is the issuer of the JWT Token (typically full URL of your auth0 tenant account - eg. https://{tenant_name}.auth0.com/)

`auth0.clientId` - This is the client id of your auth0 application (see Settings page on auth0 dashboard)

`auth0.clientSecret` - This is the client secret of your auth0 application (see Settings page on auth0 dashboard)

`auth0.securedRoute`: - This is the URL pattern to secure a URL endpoint. Should start with `/` Note, if you are using the default library configuration (not overriding with
your own) which just secures a single, specific context path then this value is important. However, if you are building an application which may have several different
secured endpoints, or you don't want / need to specify an explicit configuration value in this .properties file then just set the value to something that signifies this.
Perhaps `auth0.securedRoute: UNUSED`. Then just ignore the `securedRoute` entirely when you specify your own configuration. See the section `Extending Auth0SecurityConfig`
below for further info. The takeaway message is that this property value is a convenience for the developer to configure an endpoint by context path
(.eg all URLS with `/api/v1/` in their context path) - but there is no obligation to actually reference this property in your own HttpSecurity configuration.

`auth0.base64EncodedSecret` - This is a boolean value indicating whether the Secret used to verify the JWT is base64 encoded. Default is `true`

`auth0.authorityStrategy` - This indicates whether authorization `claims` against the Principal shall be `GROUPS`, `ROLES` or `SCOPE` based. Default is `ROLES`

`auth0.defaultAuth0ApiSecurityEnabled` - This is a boolean value that switches having the default config enabled. Should be `false`

The default JWT Signing Algorithm is `HS256`. This is HMAC SHA256, a symmetric crypographic algorithm (HMAC), that uses the `clientSecret` to
verify a signed JWT token. However, if you wish to configure this library to use an alternate cryptographic algorithm then use the two
options below. The Auth0 Dashboard offers the choice between `HS256` and `RS256`. 'RS256' is RSA SHA256 and uses a public key cryptographic
algorithm (RSA), that requires knowledge of the application public key to verify a signed JWT Token (that was signed with a private key).
You can download the application's public key from the Auth0 Dashboard and store it inside your application's WEB-INF directory. 

The following two attributes are required when configuring your application with this library to use `RSA` instead of `HMAC`:

`auth0.signingAlgorithm` - This is signing algorithm to verify signed JWT token. Use `HS256` or `RS256`. 

`auth0.publicKeyPath` - This is the path location to the public key stored locally on disk / inside your application War file. Should always be set when using `RS256`. 


### Extending Auth0SecurityConfig

Contained in this library is a security configuration class (using Spring Java Configuration Annotations) called `Auth0SecurityConfig`.
It handles all the library Application Context wiring configuration, and a default `HttpSecurity` endpoint configuration that by default
simply secures the URL Context path defined with `auth0.securedRoute` property (see properties configuration instructions above).

This is defined in a method called `authorizeRequests(final HttpSecurity http)` - which is intentionally meant for being overridden.
In almost all cases, it is expected that Client Applications using this library will do so.

```
/**
     * Lightweight default configuration that offers basic authorization checks for authenticated
     * users on secured endpoint, and sets up a Principal user object with granted authorities
     * <p>
     * For simple apps, this is sufficient, however for applications wishing to specify fine-grained
     * endpoint access restrictions, use Role / Group level endpoint authorization etc, then this configuration
     * should be disabled and a copy, augmented with your own requirements provided. See Sample app for example
     *
     * Override this function in subclass to apply custom authentication / authorization
     * strategies to your application endpoints
     */
    protected void authorizeRequests(final HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(securedRoute).authenticated()
                .antMatchers("/**").permitAll();
    }
 ```

For example, from the Sample application here is the declared subclass together with overridden method:

```
package com.auth0.example;

import com.auth0.spring.security.api.Auth0SecurityConfig;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;


@Configuration
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class AppConfig extends Auth0SecurityConfig {

    @Override
    protected void authorizeRequests(final HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/ping").permitAll()
                .antMatchers(HttpMethod.GET, "/api/v1/profiles").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
                .antMatchers(HttpMethod.GET, "/api/v1/profiles/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
                .antMatchers(HttpMethod.POST, "/api/v1/profiles/**").hasAnyAuthority("ROLE_ADMIN")
                .antMatchers(HttpMethod.PUT, "/api/v1/profiles/**").hasAnyAuthority("ROLE_ADMIN")
                .antMatchers(HttpMethod.DELETE, "/api/v1/profiles/**").hasAnyAuthority("ROLE_ADMIN")
                .antMatchers(securedRoute).authenticated();
    }

}
```

By subclassing, and overriding `authorizeRequests` as above, you are free to define whatever endpoint security configuration (authentication and
authorization) suitable for your own needs.

----

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
