package com.auth0.spring.security.api;

import com.auth0.spring.security.api.authentication.AuthenticationJsonWebTokenFactory;
import com.auth0.spring.security.api.authentication.PreAuthenticatedAuthenticationJsonWebToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BearerSecurityContextRepository implements SecurityContextRepository {
    private final static Logger logger = LoggerFactory.getLogger(BearerSecurityContextRepository.class);
    private final AuthenticationJsonWebTokenFactory tokenFactory;
    public BearerSecurityContextRepository() {
        this(new AuthenticationJsonWebTokenFactory());
    }
    public BearerSecurityContextRepository(AuthenticationJsonWebTokenFactory tokenFactory) {
        this.tokenFactory = tokenFactory;
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        String token = tokenFromRequest(requestResponseHolder.getRequest());
        Authentication authentication = tokenFactory.usingToken(token);
        if (authentication != null) {
            context.setAuthentication(authentication);
            logger.debug("Found bearer token in request. Saving it in SecurityContext");
        }
        return context;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return tokenFromRequest(request) != null;
    }

    private String tokenFromRequest(HttpServletRequest request) {
        final String value = request.getHeader("Authorization");

        if (value == null || !value.toLowerCase().startsWith("bearer")) {
            return null;
        }

        String[] parts = value.split(" ");

        if (parts.length < 2) {
            return null;
        }

        return parts[1].trim();
    }
}
