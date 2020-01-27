package com.auth0.spring.security.api.authentication;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

class AuthoritiesExtractor {

    private final static String SCOPE_AUTHORITY_PREFIX = "SCOPE_";
    private final static String PERMISSION_AUTHORITY_PREFIX = "PERMISSION_";

    private final DecodedJWT decoded;
    private final List<String> customClaims;

    AuthoritiesExtractor(DecodedJWT decoded, List<String> customClaims) {
        this.decoded = decoded;
        this.customClaims = customClaims;
    }

    Collection<? extends GrantedAuthority> extractAuthorities() {
        Collection<? extends GrantedAuthority> permissions = getPermissionAuthorities();
        Collection<? extends GrantedAuthority> scopes = getScopeAuthorities();
        Collection<? extends GrantedAuthority> customClaims = getCustomClaimAuthorities();

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.addAll(scopes);
        authorities.addAll(permissions);
        authorities.addAll(customClaims);

        return authorities;
    }

    private List<SimpleGrantedAuthority> getScopeAuthorities() {
        List<SimpleGrantedAuthority> prefixedAuthorities = extractAuthorities("scope", SCOPE_AUTHORITY_PREFIX);
        List<SimpleGrantedAuthority> unprefixedAuthorities = extractAuthorities("scope", "");

        List<SimpleGrantedAuthority> scopeAuthorities = new ArrayList<>();
        scopeAuthorities.addAll(prefixedAuthorities);
        scopeAuthorities.addAll(unprefixedAuthorities);
        return scopeAuthorities;
    }

    private List<SimpleGrantedAuthority> getPermissionAuthorities() {
        return extractAuthorities("permissions", PERMISSION_AUTHORITY_PREFIX);
    }

    private List<SimpleGrantedAuthority> getCustomClaimAuthorities() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        if (customClaims == null || customClaims.isEmpty()) {
            return authorities;
        }
        for (String claim : customClaims) {
            authorities.addAll(extractAuthorities(claim, claim + "_"));
        }
        return authorities;
    }

    private List<SimpleGrantedAuthority> extractAuthorities(String claim, String authorityPrefix) {
        String claimValues = decoded.getClaim(claim).asString();
        if (claimValues != null && !claimValues.trim().isEmpty()) {
            return extractStringClaimAuthorities(claim, authorityPrefix, claimValues);
        }
        String[] arrayClaimValues = decoded.getClaim(claim).asArray(String.class);
        if (arrayClaimValues != null && arrayClaimValues.length > 0) {
            return extractArrayAuthorities(claim, authorityPrefix, arrayClaimValues);
        }
        return Collections.emptyList();
    }

    private List<SimpleGrantedAuthority> extractArrayAuthorities(String claim, String authorityPrefix, String[] arrayClaimValues) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>(arrayClaimValues.length);
        for (String value : arrayClaimValues) {
            authorities.add(new SimpleGrantedAuthority(authorityPrefix + value));
        }

        return authorities;
    }

    private List<SimpleGrantedAuthority> extractStringClaimAuthorities(String claim, String authorityPrefix, String claimValues) {
        if (claimValues == null || claimValues.trim().isEmpty()) {
            return Collections.emptyList();
        }
        final String[] customClaims = claimValues.split(" ");
        List<SimpleGrantedAuthority> authorities = new ArrayList<>(customClaims.length);
        for (String value : customClaims) {
            authorities.add(new SimpleGrantedAuthority(authorityPrefix + value));
        }
        return authorities;
    }
}
