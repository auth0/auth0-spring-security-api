package com.auth0.spring.security.api;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.*;

public class JwtAuthentication implements Authentication {

    private final String token;
    private final Map<String, Object> decoded;
    private boolean authenticated;

    public JwtAuthentication(String token) {
        this.token = token;
        this.authenticated = false;
        this.decoded = new HashMap<>();
    }

    public JwtAuthentication(String token, Map<String, Object> decoded) {
        this.token = token;
        this.authenticated = true;
        this.decoded = new HashMap<>(decoded);

    }

    public String getToken() {
        return token;
    }

    public String getKeyId() {
        final String[] parts = getToken().split("\\.");
        if (parts.length != 3) {
            return null;
        }

        String json = new String(Base64.decodeBase64(parts[0]));
        final JsonFactory factory = new JsonFactory();
        try {
            final JsonParser parser = factory.createParser(json);
            final TypeReference<Map<String, Object>> typeReference = new TypeReference<Map<String, Object>>() {
            };
            Map<String, Object> values = new ObjectMapper().reader().readValue(parser, typeReference);
            return (String) values.get("kid");
        } catch (IOException e) {
            return null;
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        String scope = (String) decoded.get("scope");
        if (scope == null || scope.trim().isEmpty()) {
            return new ArrayList<>();
        }
        final String[] scopes = scope.split(" ");
        List<SimpleGrantedAuthority> authorities = new ArrayList<>(scopes.length);
        for (String value: scopes) {
            authorities.add(new SimpleGrantedAuthority(value));
        }
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getDetails() {
        return new HashMap<>(decoded);
    }

    @Override
    public Object getPrincipal() {
        return decoded.get("sub");
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
        return (String) decoded.get("sub");
    }
}
