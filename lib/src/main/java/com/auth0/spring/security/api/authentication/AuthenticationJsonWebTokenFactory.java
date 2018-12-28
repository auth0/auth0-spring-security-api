package com.auth0.spring.security.api.authentication;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.List;

public class AuthenticationJsonWebTokenFactory {
    private static Logger logger = LoggerFactory.getLogger(AuthenticationJsonWebTokenFactory.class);

    private final List<String> authorityClaims;
    public final static String DEFAULT_SCOPE="scope";
    public AuthenticationJsonWebTokenFactory() {
        this(Collections.singletonList(DEFAULT_SCOPE));
    }
    public AuthenticationJsonWebTokenFactory(List<String> authorityClaims) {
        this.authorityClaims = authorityClaims;
    }

    public PreAuthenticatedAuthenticationJsonWebToken usingToken(String token) {
        if (token == null) {
            logger.debug("No token was provided to build {}", PreAuthenticatedAuthenticationJsonWebToken.class.getName());
            return null;
        }
        try {
            DecodedJWT jwt = JWT.decode(token);
            return new PreAuthenticatedAuthenticationJsonWebToken(jwt, this);
        } catch (JWTDecodeException e) {
            logger.debug("Failed to decode token as jwt", e);
            return null;
        }
    }


    public AuthenticationJsonWebToken usingTokenAndVerifier(String token, JWTVerifier verifier) {
        return new AuthenticationJsonWebToken(token, verifier, authorityClaims, this);
    }
}
