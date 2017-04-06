package com.auth0.spring.security.api.authentication;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class AuthenticationJsonWebToken implements Authentication, JwtAuthentication {

    private final DecodedJWT decoded;
    private boolean authenticated;

    AuthenticationJsonWebToken(String token, JWTVerifier verifier) throws JWTVerificationException {
        this.decoded = verifier == null ? JWT.decode(token) : verifier.verify(token);
        this.authenticated = verifier != null;
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
        return new AuthenticationJsonWebToken(getToken(), verifier);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        String scope = decoded.getClaim("scope").asString();
        if (scope == null || scope.trim().isEmpty()) {
            return new ArrayList<>();
        }
        final String[] scopes = scope.split(" ");
        List<SimpleGrantedAuthority> authorities = new ArrayList<>(scopes.length);
        for (String value : scopes) {
            authorities.add(new SimpleGrantedAuthority(value));
        }
        return authorities;
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
