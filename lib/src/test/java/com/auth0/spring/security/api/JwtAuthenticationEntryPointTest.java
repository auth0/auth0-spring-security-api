package com.auth0.spring.security.api;

import org.junit.Test;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class JwtAuthenticationEntryPointTest {

    @Test
    public void shouldReturnUnauthorized() throws Exception {
        JwtAuthenticationEntryPoint entryPoint = new JwtAuthenticationEntryPoint();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        AuthenticationException exception = mock(AuthenticationException.class);

        entryPoint.commence(request, response, exception);
        verify(response).addHeader(
                "WWW-Authenticate",
                "Bearer error=\"Invalid access token\""
        );
        verify(response).sendError(401, "Unauthorized");
    }
}