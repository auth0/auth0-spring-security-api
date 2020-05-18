package com.auth0.spring.security.api;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import org.apache.commons.codec.binary.Base64;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

/**
 * Utility class for configuring Security for your Spring API
 */
public class JwtWebSecurityConfigurer {

    final String audience;
    final String issuer;
    final AuthenticationProvider provider;

    private JwtWebSecurityConfigurer(String audience, String issuer, AuthenticationProvider authenticationProvider) {
        this.audience = audience;
        this.issuer = issuer;
        this.provider = authenticationProvider;
    }

    /**
     * Configures application authorization for JWT signed with RS256.
     * Will try to validate the token using the public key downloaded from "$issuer/.well-known/jwks.json"
     * and matched by the value of {@code kid} of the JWT header
     * @param audience identifier of the API and must match the {@code aud} value in the token
     * @param issuer of the token for this API and must match the {@code iss} value in the token
     * @return JwtWebSecurityConfigurer for further configuration
     */
    @SuppressWarnings({"WeakerAccess", "SameParameterValue"})
    public static JwtWebSecurityConfigurer forRS256(String audience, String issuer) {
        final JwkProvider jwkProvider = new JwkProviderBuilder(issuer).build();
        return new JwtWebSecurityConfigurer(audience, issuer, new JwtAuthenticationProvider(jwkProvider, issuer, audience));
    }

    /**
     * Configures application authorization for JWT signed with RS256
     * Will try to validate the token using the public key downloaded from "$issuer/.well-known/jwks.json"
     * and matched by the value of {@code kid} of the JWT header
     * @param audience identifier of the API and must match the {@code aud} value in the token
     * @param issuer of the token for this API and must match the {@code iss} value in the token
     * @param provider of Spring Authentication objects that can validate a {@link com.auth0.spring.security.api.authentication.PreAuthenticatedAuthenticationJsonWebToken}
     * @return JwtWebSecurityConfigurer for further configuration
     */
    @SuppressWarnings({"WeakerAccess", "SameParameterValue"})
    public static JwtWebSecurityConfigurer forRS256(String audience, String issuer, AuthenticationProvider provider) {
        return new JwtWebSecurityConfigurer(audience, issuer, provider);
    }

    /**
     * Configures application authorization for JWT signed with HS256
     * @param audience identifier of the API and must match the {@code aud} value in the token
     * @param issuer of the token for this API and must match the {@code iss} value in the token
     * @param secret used to sign and verify tokens encoded in Base64
     * @return JwtWebSecurityConfigurer for further configuration
     */
    @SuppressWarnings({"WeakerAccess", "SameParameterValue"})
    public static JwtWebSecurityConfigurer forHS256WithBase64Secret(String audience, String issuer, String secret) {
        final byte[] secretBytes = new Base64(true).decode(secret);
        return new JwtWebSecurityConfigurer(audience, issuer, new JwtAuthenticationProvider(secretBytes, issuer, audience));
    }

    /**
     * Configures application authorization for JWT signed with HS256
     * @param audience identifier of the API and must match the {@code aud} value in the token
     * @param issuer of the token for this API and must match the {@code iss} value in the token
     * @param secret used to sign and verify tokens
     * @return JwtWebSecurityConfigurer for further configuration
     */
    @SuppressWarnings({"WeakerAccess", "SameParameterValue"})
    public static JwtWebSecurityConfigurer forHS256(String audience, String issuer, byte[] secret) {
        return new JwtWebSecurityConfigurer(audience, issuer, new JwtAuthenticationProvider(secret, issuer, audience));
    }

    /**
     * Configures application authorization for JWT signed with HS256
     * @param audience identifier of the API and must match the {@code aud} value in the token
     * @param issuer of the token for this API and must match the {@code iss} value in the token
     * @param provider of Spring Authentication objects that can validate a {@link com.auth0.spring.security.api.authentication.PreAuthenticatedAuthenticationJsonWebToken}
     * @return JwtWebSecurityConfigurer for further configuration
     */
    @SuppressWarnings({"WeakerAccess", "SameParameterValue"})
    public static JwtWebSecurityConfigurer forHS256(String audience, String issuer, AuthenticationProvider provider) {
        return new JwtWebSecurityConfigurer(audience, issuer, provider);
    }

    /**
     * Further configure the {@link HttpSecurity} object with some sensible defaults
     * by registering objects to obtain a bearer token from a request.
     * @param http configuration for Spring
     * @return the http configuration for further customizations
     * @throws Exception
     */
    @SuppressWarnings("unused")
    public HttpSecurity configure(HttpSecurity http) throws Exception {
        return http
                .authenticationProvider(provider)
                .securityContext()
                .securityContextRepository(new BearerSecurityContextRepository())
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new JwtAuthenticationEntryPoint(audience, issuer))
                .and()
                .httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and();
    }
}
