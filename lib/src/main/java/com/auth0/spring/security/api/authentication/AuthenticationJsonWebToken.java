package com.auth0.spring.security.api.authentication;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;
import java.util.List;


public class AuthenticationJsonWebToken implements Authentication, JwtAuthentication {

    private final DecodedJWT decoded;
    private boolean authenticated;
    private final AuthoritiesExtractor authoritiesExtractor;

    AuthenticationJsonWebToken(String token, JWTVerifier verifier) throws JWTVerificationException {
        this(token, verifier, Collections.<String>emptyList());
    }

    AuthenticationJsonWebToken(String token, JWTVerifier verifier, List<String> customClaims) throws JWTVerificationException {
        this.decoded = verifier == null ? JWT.decode(token) : verifier.verify(token);
        this.authenticated = verifier != null;
        this.authoritiesExtractor = new AuthoritiesExtractor(decoded, customClaims);
    }

    @Override
    public String getToken() {
        return decoded.getToken();
    }

    @Override
    public String getKeyId() {
        return decoded.getKeyId();
    }

    @Override
    public Authentication verify(JWTVerifier verifier) throws JWTVerificationException {
        return verify(verifier, null);
    }

    @Override
    public Authentication verify(JWTVerifier verifier, List<String> customClaims) throws JWTVerificationException {
        return new AuthenticationJsonWebToken(getToken(), verifier, customClaims);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authoritiesExtractor.extractAuthorities();
    }

    @Override
    public Object getCredentials() {
        return decoded.getToken();
    }

    @Override
    public Object getDetails() {
        return decoded;
    }

    @Override
    public Object getPrincipal() {
        return decoded.getSubject();
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException("Must create a new instance to specify that the authentication is valid");
        }
        this.authenticated = false;
    }

    @Override
    public String getName() {
        return decoded.getSubject();
    }
}
