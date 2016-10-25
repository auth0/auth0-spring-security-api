package com.auth0.spring.security.api;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Implementation of the org.springframework.security.core.Authentication interface.
 * Spring Security Container for Principal (user profile) and JWT
 */
public class Auth0JWTToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 2371882820082543721L;

	private final String jwt;
	private Auth0UserDetails principal;

	public Auth0JWTToken(final String jwt) {
		super(null);
		this.jwt = jwt;
		setAuthenticated(false);
	}

	public String getJwt() {
		return jwt;
	}

	public Object getCredentials() {
		return null;
	}

	public Object getPrincipal() {
		return principal;
	}

	public void setPrincipal(Auth0UserDetails principal) {
		this.principal = principal;
	}

	@SuppressWarnings("unchecked")
	@Override
    public Collection<GrantedAuthority> getAuthorities() {
		return (Collection<GrantedAuthority>) principal.getAuthorities();
     }

}
