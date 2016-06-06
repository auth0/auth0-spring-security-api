package com.auth0.example;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;

@Configuration
@PropertySources({
        @PropertySource("classpath:application.properties"),
        @PropertySource("classpath:auth0.properties")
})
public class AppConfig {

    @Value(value = "${auth0.clientId}")
    private String clientId;

    @Value(value = "${auth0.clientSecret}")
    private String clientSecret;

    @Value(value = "${auth0.domain}")
    private String issuer;

    @Value(value = "${auth0.securedRoute}")
    protected String securedRoute;

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    // Not required for the Spring Security implementation, but offers Auth0 API access
    @Bean
    public Auth0Client auth0Client() {
        return new Auth0Client(clientId, issuer);
    }

}