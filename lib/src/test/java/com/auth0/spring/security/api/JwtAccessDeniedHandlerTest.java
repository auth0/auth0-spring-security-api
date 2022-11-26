package com.auth0.spring.security.api;

import org.junit.Test;
import org.springframework.security.access.AccessDeniedException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class JwtAccessDeniedHandlerTest {

    @Test
    public void shouldReturnForbidden() throws Exception {
        JwtAccessDeniedHandler handler = new JwtAccessDeniedHandler();
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        AccessDeniedException exception = new AccessDeniedException("Forbidden");

        handler.handle(request, response, exception);
        verify(response).addHeader(
                "WWW-Authenticate",
                "Bearer error=\"Insufficient scope\""
        );
        verify(response).sendError(403, "Forbidden");
    }
}
