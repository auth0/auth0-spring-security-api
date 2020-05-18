package com.auth0.spring.security.api;

import org.junit.Test;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.*;

public class JwtAuthenticationEntryPointTest {

    @Test
    public void shouldReturnUnauthorized() throws Exception {
        JwtAuthenticationEntryPoint entryPoint = new JwtAuthenticationEntryPoint("https://api.example.org/", "https://example.auth0.com/");
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        AuthenticationException exception = mock(AuthenticationException.class);

        entryPoint.commence(request, response, exception);
        verify(response).addHeader(
                "WWW-Authenticate",
                "Bearer realm=\"https://api.example.org/\", authorization_uri=\"https://example.auth0.com/oauth/token\""
        );
        verify(response).sendError(401, "Unauthorized");
    }

}