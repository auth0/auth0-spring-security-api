package com.auth0.spring.security.api;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

public abstract class Auth0TokenHelper<T> implements InitializingBean {

    public static final String VALID_ISSUER = "YOUR_ISSUER";
    public static final String VALID_AUDIENCE = "YOUR_CLIENT_ID";

    private String clientSecret = null;
    private String clientId = null;

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(clientSecret, "The client secret is not set for " + this.getClass());
        Assert.notNull(clientId, "The client id is not set for " + this.getClass());
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public abstract String generateToken(T object, String issuer, String audience, long expiration);

    public abstract T decodeToken(String token);

}
