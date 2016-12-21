package com.auth0.spring.security.api.authentication;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.security.core.Authentication;

public interface JwtAuthentication {

    String getToken();

    String getKeyId();

    Authentication verify(JWTVerifier verifier) throws JWTVerificationException;
}
