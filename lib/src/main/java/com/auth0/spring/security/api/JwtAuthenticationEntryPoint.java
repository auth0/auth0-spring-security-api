package com.auth0.spring.security.api;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    final String audience;
    final String issuer;

    public JwtAuthenticationEntryPoint(String audience, String issuer) {
        this.audience = audience;
        this.issuer = issuer;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setHeader(
                "WWW-Authenticate",
                String.format("Bearer realm=\"%s\", authorization_uri=\"%soauth/token", this.audience, this.issuer)
        );

        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}
