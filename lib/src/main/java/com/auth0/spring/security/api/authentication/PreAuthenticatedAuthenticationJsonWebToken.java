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

public class PreAuthenticatedAuthenticationJsonWebToken extends AuthenticationJsonWebToken {

    private static Logger logger = LoggerFactory.getLogger(PreAuthenticatedAuthenticationJsonWebToken.class);

    PreAuthenticatedAuthenticationJsonWebToken(DecodedJWT token) {
        super(token);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    @Override
    public boolean isAuthenticated() {
        return false;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

    }

    public static PreAuthenticatedAuthenticationJsonWebToken usingToken(String token) {
        if (token == null) {
            logger.debug("No token was provided to build {}", PreAuthenticatedAuthenticationJsonWebToken.class.getName());
            return null;
        }
        try {
            DecodedJWT jwt = JWT.decode(token);
            return new PreAuthenticatedAuthenticationJsonWebToken(jwt);
        } catch (JWTDecodeException e) {
            logger.debug("Failed to decode token as jwt", e);
            return null;
        }
    }

    @Override
    public Authentication verify(JWTVerifier verifier) throws JWTVerificationException {
        return new AuthenticationJsonWebToken(getDecoded().getToken(), verifier);
    }
}
