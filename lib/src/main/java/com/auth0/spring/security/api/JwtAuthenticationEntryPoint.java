package com.auth0.spring.security.api;

import org.springframework.http.HttpHeaders;
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
        String modifiedIssuer = this.issuer.endsWith("/") ? this.issuer.substring(0, this.issuer.length() - 1) : this.issuer;

        response.addHeader(
                HttpHeaders.WWW_AUTHENTICATE,
                String.format("Bearer realm=\"%s\", authorization_uri=\"%s/authorize\"", this.audience, modifiedIssuer)
        );

        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}
