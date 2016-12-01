package com.auth0.spring.security.api;

import org.junit.Test;
import org.springframework.security.authentication.AuthenticationProvider;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

public class JwtWebSecurityConfigurerTest {

    @Test
    public void shouldCreateRS256Configurer() throws Exception {
        JwtWebSecurityConfigurer configurer = JwtWebSecurityConfigurer.forRS256("audience", "issuer");

        assertThat(configurer, is(notNullValue()));
        assertThat(configurer.audience, is("audience"));
        assertThat(configurer.issuer, is("issuer"));
        assertThat(configurer.provider, is(notNullValue()));
        assertThat(configurer.provider, is(instanceOf(JwtAuthenticationProvider.class)));
    }

    @Test
    public void shouldCreateRS256ConfigurerWithCustomAuthenticationProvider() throws Exception {
        AuthenticationProvider provider = mock(AuthenticationProvider.class);
        JwtWebSecurityConfigurer configurer = JwtWebSecurityConfigurer.forRS256("audience", "issuer", provider);

        assertThat(configurer, is(notNullValue()));
        assertThat(configurer.audience, is("audience"));
        assertThat(configurer.issuer, is("issuer"));
        assertThat(configurer.provider, is(notNullValue()));
        assertThat(configurer.provider, is(provider));
    }

    @Test
    public void shouldCreateHS256ConfigurerWithBase64EncodedSecret() throws Exception {
        JwtWebSecurityConfigurer configurer = JwtWebSecurityConfigurer.forHS256WithBase64Secret("audience", "issuer", "c2VjcmV0");

        assertThat(configurer, is(notNullValue()));
        assertThat(configurer.audience, is("audience"));
        assertThat(configurer.issuer, is("issuer"));
        assertThat(configurer.provider, is(notNullValue()));
        assertThat(configurer.provider, is(instanceOf(JwtAuthenticationProvider.class)));
    }

    @Test
    public void shouldCreateHS256Configurer() throws Exception {
        JwtWebSecurityConfigurer configurer = JwtWebSecurityConfigurer.forHS256("audience", "issuer", "secret".getBytes());

        assertThat(configurer, is(notNullValue()));
        assertThat(configurer.audience, is("audience"));
        assertThat(configurer.issuer, is("issuer"));
        assertThat(configurer.provider, is(notNullValue()));
        assertThat(configurer.provider, is(instanceOf(JwtAuthenticationProvider.class)));
    }

    @Test
    public void shouldCreateHS256ConfigurerWithCustomAuthenticationProvider() throws Exception {
        AuthenticationProvider provider = mock(AuthenticationProvider.class);
        JwtWebSecurityConfigurer configurer = JwtWebSecurityConfigurer.forHS256("audience", "issuer", provider);

        assertThat(configurer, is(notNullValue()));
        assertThat(configurer.audience, is("audience"));
        assertThat(configurer.issuer, is("issuer"));
        assertThat(configurer.provider, is(notNullValue()));
        assertThat(configurer.provider, is(provider));
    }
}