package com.auth0.spring.security.api.authentication;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class PreAuthenticatedAuthenticationJsonWebToken implements Authentication, JwtAuthentication {

    private static Logger logger = LoggerFactory.getLogger(PreAuthenticatedAuthenticationJsonWebToken.class);

    private final DecodedJWT token;
    private final AuthenticationJsonWebTokenFactory tokenFactory;

    PreAuthenticatedAuthenticationJsonWebToken(DecodedJWT token, AuthenticationJsonWebTokenFactory tokenFactory) {
        this.token = token;
        this.tokenFactory = tokenFactory;
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
        return tokenFactory.usingTokenAndVerifier(token.getToken(), verifier);
    }
}
