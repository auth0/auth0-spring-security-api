package com.auth0.spring.security.api;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import org.apache.commons.codec.binary.Base64;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

public class JwtWebSecurityConfigurer {

    protected final String audience;
    protected final String issuer;
    protected final AuthenticationProvider provider;

    private JwtWebSecurityConfigurer(String audience, String issuer, AuthenticationProvider authenticationProvider) {
        this.audience = audience;
        this.issuer = issuer;
        this.provider = authenticationProvider;
    }

    public static JwtWebSecurityConfigurer forRS256(String audience, String issuer) {
        final JwkProvider jwkProvider = new JwkProviderBuilder(issuer).build();
        return new JwtWebSecurityConfigurer(audience, issuer, new JwtAuthenticationProvider(jwkProvider, issuer, audience));
    }

    public static JwtWebSecurityConfigurer forRS256(String audience, String issuer, AuthenticationProvider provider) {
        return new JwtWebSecurityConfigurer(audience, issuer, provider);
    }

    public static JwtWebSecurityConfigurer forHS256WithBase64Secret(String audience, String issuer, String secret) {
        final byte[] secretBytes = new Base64(true).decode(secret);
        return new JwtWebSecurityConfigurer(audience, issuer, new JwtAuthenticationProvider(secretBytes, issuer, audience));
    }

    public static JwtWebSecurityConfigurer forHS256(String audience, String issuer, byte[] secret) {
        return new JwtWebSecurityConfigurer(audience, issuer, new JwtAuthenticationProvider(secret, issuer, audience));
    }

    public static JwtWebSecurityConfigurer forHS256(String audience, String issuer, AuthenticationProvider provider) {
        return new JwtWebSecurityConfigurer(audience, issuer, provider);
    }

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
