package com.auth0.spring.security.api;

public interface Auth0TokenHelper<T> {

    public String generateToken(T object, long expiration);

    public T decodeToken(String token);

}
