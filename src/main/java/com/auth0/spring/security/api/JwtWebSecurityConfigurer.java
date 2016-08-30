package com.auth0.spring.security.api;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import org.apache.commons.codec.binary.Base64;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

public abstract class JwtWebSecurityConfigurer {

    protected final String audience;
    protected final String issuer;

    private JwtWebSecurityConfigurer(String audience, String issuer) {
        this.audience = audience;
        this.issuer = issuer;
    }

    public abstract AuthenticationProvider newAuthenticationProvider();

    public static JwtWebSecurityConfigurer forRS256(String audience, String issuer) {
        return new RSConfigurer(audience, issuer);
    }

    public static JwtWebSecurityConfigurer forHS256WithBase64Secret(String audience, String issuer, String secret) {
        return new HSConfigurer(audience, issuer, new Base64(true).decode(secret));
    }

    public static JwtWebSecurityConfigurer forHS256(String audience, String issuer, byte[] secret) {
        return new HSConfigurer(audience, issuer, secret);
    }

    public HttpSecurity configure(HttpSecurity http) throws Exception {
        return http
                .authenticationProvider(newAuthenticationProvider())
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

    private static class HSConfigurer extends JwtWebSecurityConfigurer {
        private final byte[] secret;

        private HSConfigurer(String audience, String issuer, byte[] secret) {
            super(audience, issuer);
            this.secret = secret;
        }

        @Override
        public AuthenticationProvider newAuthenticationProvider() {
            return new JwtAuthenticationProvider(secret, issuer, audience);
        }
    }

    private static class RSConfigurer extends JwtWebSecurityConfigurer {
        private RSConfigurer(String audience, String issuer) {
            super(audience, issuer);
        }

        @Override
        public AuthenticationProvider newAuthenticationProvider() {
            final JwkProvider jwkProvider = new JwkProviderBuilder().forDomain(this.issuer).build();
            return new JwtAuthenticationProvider(jwkProvider, this.issuer, this.audience);
        }
    }
}
