package com.auth0.spring.security.api.authentication;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.security.core.Authentication;

import java.util.List;

public interface JwtAuthentication {

    String getToken();

    String getKeyId();

    Authentication verify(JWTVerifier verifier) throws JWTVerificationException;

    Authentication verify(JWTVerifier verifier, List<String> customClaims) throws JWTVerificationException;
}
