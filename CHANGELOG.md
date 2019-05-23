# Change Log

## [1.2.2](https://github.com/auth0/auth0-spring-security-api/tree/1.2.2) (2019-05-23)
[Full Changelog](https://github.com/auth0/auth0-spring-security-api/compare/1.2.1...1.2.2)

**Security**
- Bump dependencies [\#26](https://github.com/auth0/auth0-spring-security-api/pull/26) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.2.1](https://github.com/auth0/auth0-spring-security-api/tree/1.2.1) (2019-01-03)
[Full Changelog](https://github.com/auth0/auth0-spring-security-api/compare/1.2.0...1.2.1)

**Security**
- Bump dependencies to fix security issue [\#13](https://github.com/auth0/auth0-spring-security-api/pull/13) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.2.0](https://github.com/auth0/auth0-spring-security-api/tree/1.2.0) (2018-11-22)
[Full Changelog](https://github.com/auth0/auth0-spring-security-api/compare/1.1.0...1.2.0)

**Security**
- Use latest Gradle wrapper and Bump dependencies [\#4](https://github.com/auth0/auth0-spring-security-api/pull/4) ([napstr](https://github.com/napstr))

## [1.1.0](https://github.com/auth0/auth0-spring-security-api/tree/1.1.0) (2018-05-31)
[Full Changelog](https://github.com/auth0/auth0-spring-security-api/compare/1.0.0...1.1.0)

**Added**
- Allow to set a leeway for JWT verification [\#57](https://github.com/auth0/auth0-spring-security-api/pull/57) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.0.0](https://github.com/auth0/auth0-spring-security-api/tree/1.0.0) (2018-01-26)
[Full Changelog](https://github.com/auth0/auth0-spring-security-api/compare/1.0.0-rc.3...1.0.0)

**Changed**
- Remove unused guava dependency Issue #47 [\#48](https://github.com/auth0/auth0-spring-security-api/pull/48) ([rhanton](https://github.com/rhanton))

## [1.0.0-rc.3](https://github.com/auth0/auth0-spring-security-api/tree/1.0.0-rc.3) (2017-06-13)
[Full Changelog](https://github.com/auth0/auth0-spring-security-api/compare/1.0.0-rc.2...1.0.0-rc.3)

**Changed**
- Use java-jwt version 3.2.0 [\#34](https://github.com/auth0/auth0-spring-security-api/pull/34) ([lbalmaceda](https://github.com/lbalmaceda))
- Use java-jwt version 3.1.0 [\#30](https://github.com/auth0/auth0-spring-security-api/pull/30) ([pacey](https://github.com/pacey))

## [1.0.0-rc.2](https://github.com/auth0/auth0-spring-security-api/tree/1.0.0-rc.2) (2016-12-21)
[Full Changelog](https://github.com/auth0/auth0-spring-security-api/compare/1.0.0-rc.1...1.0.0-rc.2)

**Changed**
- Rework authentication classes and add more tests. [\#22](https://github.com/auth0/auth0-spring-security-api/pull/22) ([hzalaz](https://github.com/hzalaz))

## [1.0.0-rc.1](https://github.com/auth0/java-jwt/tree/1.0.0-rc.1) (2016-12-19)

Auth0 integration with Spring Security to add authorization to your API using JWTs

## Download

Get Auth0 Spring Security API using Maven:

```xml
<dependency>
    <groupId>com.github.auth0</groupId>
    <artifactId>auth0-spring-security-api</artifactId>
    <version>1.0.0-rc.1</version>
</dependency>
```

or Gradle:

```gradle
compile 'com.auth0.github:auth0-spring-security-api:1.0.0-rc.1'
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
                .forHS256WithBase64Secret("YOUR_API_AUDIENCE", "YOUR_API_ISSUER", "YOUR_BASE_64_ENCODED_SECRET")
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
