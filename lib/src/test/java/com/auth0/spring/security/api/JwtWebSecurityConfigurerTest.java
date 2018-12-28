package com.auth0.spring.security.api;

import org.hamcrest.Matchers;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.*;
import org.springframework.security.config.http.SessionCreationPolicy;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

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

    @Test
    public void shouldCreateRS256ConfigurerFullyConfigured() throws Exception {
        AuthenticationProvider provider = mock(AuthenticationProvider.class);
        BearerSecurityContextRepository bearerSecurity = mock(BearerSecurityContextRepository.class);
        JwtAuthenticationEntryPoint entryPoint = mock(JwtAuthenticationEntryPoint.class);

        //This is a final class. Mocked using https://github.com/mockito/mockito/wiki/What's-new-in-Mockito-2#mock-the-unmockable-opt-in-mocking-of-final-classesmethods
        // Due to lack of verifiability, we create multiple HttpSecurity mocks to ensure each method is invoked
        HttpSecurity httpSecurity = mock(HttpSecurity.class);
        HttpSecurity httpSecurityChain1 = mock(HttpSecurity.class);
        HttpSecurity httpSecurityChain2 = mock(HttpSecurity.class);
        HttpSecurity httpSecurityChain3 = mock(HttpSecurity.class);
        HttpSecurity httpSecurityChain4 = mock(HttpSecurity.class);
        HttpSecurity httpSecurityChain5 = mock(HttpSecurity.class);
        HttpSecurity httpSecurityFinal = mock(HttpSecurity.class);

        when(httpSecurity.authenticationProvider(provider)).thenReturn(httpSecurityChain1);
        SecurityContextConfigurer<HttpSecurity> securityConfigurer = mock(SecurityContextConfigurer.class);
        when(httpSecurityChain1.securityContext()).thenReturn(securityConfigurer);
        when(securityConfigurer.securityContextRepository(bearerSecurity)).thenReturn(securityConfigurer);
        when(securityConfigurer.and()).thenReturn(httpSecurityChain2);

        ExceptionHandlingConfigurer<HttpSecurity> exceptionConfigurer = mock(ExceptionHandlingConfigurer.class);
        when(httpSecurityChain2.exceptionHandling()).thenReturn(exceptionConfigurer);
        when(exceptionConfigurer.authenticationEntryPoint(entryPoint)).thenReturn(exceptionConfigurer);
        when(exceptionConfigurer.and()).thenReturn(httpSecurityChain3);

        HttpBasicConfigurer<HttpSecurity> basicConfigurer = mock(HttpBasicConfigurer.class);
        when (httpSecurityChain3.httpBasic()).thenReturn(basicConfigurer);
        when(basicConfigurer.disable()).thenReturn(httpSecurityChain4);

        CsrfConfigurer<HttpSecurity> csrfSecurity = mock(CsrfConfigurer.class);
        when(httpSecurityChain4.csrf()).thenReturn(csrfSecurity);
        when(csrfSecurity.disable()).thenReturn(httpSecurityChain5);

        SessionManagementConfigurer<HttpSecurity> sessionConfigurer = mock(SessionManagementConfigurer.class);
        when(httpSecurityChain5.sessionManagement()).thenReturn(sessionConfigurer);
        when(sessionConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).thenReturn(sessionConfigurer);
        when(sessionConfigurer.and()).thenReturn(httpSecurityFinal);


        JwtWebSecurityConfigurer configurer = JwtWebSecurityConfigurer.forRS256("audience", "issuer", provider);

        HttpSecurity configuredHttpSecurity = configurer.configure(httpSecurity, bearerSecurity, entryPoint);

        // This does not test everything unfortunately but it does check that each section of configuration is called
        assertThat(configuredHttpSecurity, Matchers.is(httpSecurityFinal));

        // most things can not be verified with Mockito due to final classes being used
//        verify(exceptionConfigurer.authenticationEntryPoint(entryPoint));
//        verify(securityConfigurer.securityContextRepository(bearerSecurity));
//        verify(basicConfigurer.disable());
//        verify(csrfSecurity.disable());
//        verify(sessionConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS));




    }

}