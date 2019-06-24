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
    final String[] issuers;
    final AuthenticationProvider provider;

    private JwtWebSecurityConfigurer(String audience, String[] issuers, AuthenticationProvider authenticationProvider) {
        this.audience = audience;
        this.issuers = issuers;
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
        return forRS256(audience, new String[]{issuer});
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
        return forRS256(audience, new String[]{issuer}, provider);
    }

    /**
     * Configures application authorization for JWT signed with RS256.
     * Will try to validate the token using the public key downloaded from "$issuer/.well-known/jwks.json"
     * and matched by the value of {@code kid} of the JWT header
     * @param audience identifier of the API and must match the {@code aud} value in the token
     * @param issuers array of allowed issuers of the token for this API and one of the entries must match the {@code iss} value in the token
     * @return JwtWebSecurityConfigurer for further configuration
     */
    @SuppressWarnings({"WeakerAccess", "SameParameterValue"})
    public static JwtWebSecurityConfigurer forRS256(String audience, String[] issuers) {
        final JwkProvider jwkProvider = new JwkProviderBuilder(issuers[0]).build(); // we use the first issuer for getting the jwkProvider
        return new JwtWebSecurityConfigurer(audience, issuers, new JwtAuthenticationProvider(jwkProvider, issuers, audience));
    }

    /**
     * Configures application authorization for JWT signed with RS256
     * Will try to validate the token using the public key downloaded from "$issuer/.well-known/jwks.json"
     * and matched by the value of {@code kid} of the JWT header
     * @param audience identifier of the API and must match the {@code aud} value in the token
     * @param issuers array of allowed issuers of the token for this API and one of the entries must match the {@code iss} value in the token
     * @param provider of Spring Authentication objects that can validate a {@link com.auth0.spring.security.api.authentication.PreAuthenticatedAuthenticationJsonWebToken}
     * @return JwtWebSecurityConfigurer for further configuration
     */
    @SuppressWarnings({"WeakerAccess", "SameParameterValue"})
    public static JwtWebSecurityConfigurer forRS256(String audience, String[] issuers, AuthenticationProvider provider) {
        return new JwtWebSecurityConfigurer(audience, issuers, provider);
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
        return forHS256WithBase64Secret(audience, new String[]{issuer}, secret);
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
        return forHS256(audience, new String[]{issuer}, secret);
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
        return forHS256(audience, new String[]{issuer}, provider);
    }

    /**
     * Configures application authorization for JWT signed with HS256
     * @param audience identifier of the API and must match the {@code aud} value in the token
     * @param issuers array of allowed issuers of the token for this API and one of the entries must match the {@code iss} value in the token
     * @param secret used to sign and verify tokens encoded in Base64
     * @return JwtWebSecurityConfigurer for further configuration
     */
    @SuppressWarnings({"WeakerAccess", "SameParameterValue"})
    public static JwtWebSecurityConfigurer forHS256WithBase64Secret(String audience, String[] issuers, String secret) {
        final byte[] secretBytes = new Base64(true).decode(secret);
        return new JwtWebSecurityConfigurer(audience, issuers, new JwtAuthenticationProvider(secretBytes, issuers, audience));
    }

    /**
     * Configures application authorization for JWT signed with HS256
     * @param audience identifier of the API and must match the {@code aud} value in the token
     * @param issuers array of allowed issuers of the token for this API and one of the entries must match the {@code iss} value in the token
     * @param secret used to sign and verify tokens
     * @return JwtWebSecurityConfigurer for further configuration
     */
    @SuppressWarnings({"WeakerAccess", "SameParameterValue"})
    public static JwtWebSecurityConfigurer forHS256(String audience, String[] issuers, byte[] secret) {
        return new JwtWebSecurityConfigurer(audience, issuers, new JwtAuthenticationProvider(secret, issuers, audience));
    }

    /**
     * Configures application authorization for JWT signed with HS256
     * @param audience identifier of the API and must match the {@code aud} value in the token
     * @param issuers list of allowed issuers of the token for this API and one of the entries must match the {@code iss} value in the token
     * @param provider of Spring Authentication objects that can validate a {@link com.auth0.spring.security.api.authentication.PreAuthenticatedAuthenticationJsonWebToken}
     * @return JwtWebSecurityConfigurer for further configuration
     */
    @SuppressWarnings({"WeakerAccess", "SameParameterValue"})
    public static JwtWebSecurityConfigurer forHS256(String audience, String[] issuers, AuthenticationProvider provider) {
        return new JwtWebSecurityConfigurer(audience, issuers, provider);
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
                .authenticationEntryPoint(new JwtAuthenticationEntryPoint())
                .and()
                .httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and();
    }
}
