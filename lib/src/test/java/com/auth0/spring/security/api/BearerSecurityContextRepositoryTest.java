package com.auth0.spring.security.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.spring.security.api.authentication.AuthenticationJsonWebToken;
import com.auth0.spring.security.api.authentication.AuthenticationJsonWebTokenFactory;
import com.auth0.spring.security.api.authentication.JwtAuthentication;
import com.auth0.spring.security.api.authentication.PreAuthenticatedAuthenticationJsonWebToken;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpRequestResponseHolder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.Mockito.*;

public class BearerSecurityContextRepositoryTest {

    @Test
    public void shouldDoNothingOnContextSave() throws Exception {
        BearerSecurityContextRepository repository = new BearerSecurityContextRepository();
        SecurityContext context = mock(SecurityContext.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        verifyNoMoreInteractions(context, request, response);
        repository.saveContext(context, request, response);
    }

    @Test
    public void shouldLoadContextWithoutAuthenticationIfMissingAuthorizationHeader() throws Exception {
        BearerSecurityContextRepository repository = new BearerSecurityContextRepository();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, null);

        SecurityContext context = repository.loadContext(holder);
        assertThat(context, is(notNullValue()));
        assertThat(context.getAuthentication(), is(nullValue()));
    }

    @Test
    public void shouldLoadContextWithoutAuthenticationIfInvalidAuthorizationHeaderValue() throws Exception {
        BearerSecurityContextRepository repository = new BearerSecurityContextRepository();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, null);
        when(request.getHeader("Authorization")).thenReturn("Bearer  <Invalid>");

        SecurityContext context = repository.loadContext(holder);
        assertThat(context, is(notNullValue()));
        assertThat(context.getAuthentication(), is(nullValue()));
    }

    @Test
    public void shouldLoadContextWithoutAuthenticationIfEmptyAuthorizationHeaderValue() throws Exception {
        BearerSecurityContextRepository repository = new BearerSecurityContextRepository();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, null);
        when(request.getHeader("Authorization")).thenReturn("Bearer");

        SecurityContext context = repository.loadContext(holder);
        assertThat(context, is(notNullValue()));
        assertThat(context.getAuthentication(), is(nullValue()));
    }

    @Test
    public void shouldLoadContextWithoutAuthenticationIfAuthorizationHeaderValueNotBearerToken() throws Exception {
        BearerSecurityContextRepository repository = new BearerSecurityContextRepository();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, null);
        when(request.getHeader("Authorization")).thenReturn("Basic somevalue");

        SecurityContext context = repository.loadContext(holder);
        assertThat(context, is(notNullValue()));
        assertThat(context.getAuthentication(), is(nullValue()));
    }


    @Test
    public void shouldLoadContextWithAuthentication() throws Exception {
        String token = JWT.create()
                .sign(Algorithm.HMAC256("secret"));
        BearerSecurityContextRepository repository = new BearerSecurityContextRepository();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, null);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        SecurityContext context = repository.loadContext(holder);
        assertThat(context, is(notNullValue()));
        assertThat(context.getAuthentication(), is(notNullValue()));
        assertThat(context.getAuthentication(), is(instanceOf(PreAuthenticatedAuthenticationJsonWebToken.class)));
        assertThat(context.getAuthentication().isAuthenticated(), is(false));
    }

    @Test
    public void shouldLoadContextWithCustomBearerSecurityContext() throws Exception {
        String token = JWT.create()
                .sign(Algorithm.HMAC256("secret"));
        AuthenticationJsonWebTokenFactory tokenFactory = mock(AuthenticationJsonWebTokenFactory.class);
        JwtAuthentication mockAuthentication = mock(JwtAuthentication.class);
        when(tokenFactory.usingToken(token)).thenReturn(mockAuthentication);
        BearerSecurityContextRepository repository = new BearerSecurityContextRepository(tokenFactory);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, null);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        SecurityContext context = repository.loadContext(holder);
        assertThat(context, is(notNullValue()));
        assertThat(context.getAuthentication(), is(mockAuthentication));
    }



}