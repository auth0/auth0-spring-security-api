package com.auth0.spring.security.api.authentication;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.spring.security.api.JwtAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

public class PreAuthenticatedAuthenticationJsonWebToken implements Authentication, JwtAuthentication {

    private static Logger logger = LoggerFactory.getLogger(JwtAuthenticationProvider.class);

    private final JWT token;

    PreAuthenticatedAuthenticationJsonWebToken(JWT token) {
        this.token = token;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    @Override
    public Object getCredentials() {
        return token.getToken();
    }

    @Override
    public Object getDetails() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return token.getSubject();
    }

    @Override
    public boolean isAuthenticated() {
        return false;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

    }

    @Override
    public String getName() {
        return token.getSubject();
    }

    public static PreAuthenticatedAuthenticationJsonWebToken usingToken(String token) {
        if (token == null) {
            logger.debug("No token was provided to build {}", PreAuthenticatedAuthenticationJsonWebToken.class.getName());
            return null;
        }
        try {
            JWT jwt = JWT.decode(token);
            return new PreAuthenticatedAuthenticationJsonWebToken(jwt);
        } catch (JWTDecodeException e) {
            logger.debug("Failed to decode token as jwt", e);
            return null;
        }
    }

    @Override
    public String getToken() {
        return token.getToken();
    }

    @Override
    public String getKeyId() {
        return token.getKeyId();
    }

    @Override
    public Authentication verify(JWTVerifier verifier) throws JWTVerificationException {
        return new AuthenticationJsonWebToken(token.getToken(), verifier);
    }
}
