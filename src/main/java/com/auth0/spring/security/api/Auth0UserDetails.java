package com.auth0.spring.security.api;

import com.auth0.spring.security.api.authority.AuthorityStrategy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * Implementation of UserDetails in compliance with the decoded object returned by the Auth0 JWT
 */
public class Auth0UserDetails implements UserDetails {

    private static final long serialVersionUID = 2058797193125711681L;

    private Map<String, Object> details;
    private String username;
    private boolean emailVerified;
    private Collection<GrantedAuthority> authorities = null;


    @SuppressWarnings("unchecked")
    public Auth0UserDetails(final Map<String, Object> map, final AuthorityStrategy authorityStrategy) {
        this.details = map;
        if (map.containsKey("email")) {
            this.username = map.get("email").toString();
        } else if (map.containsKey("username")) {
            this.username = map.get("username").toString();
        } else if (map.containsKey("user_id")) {
            this.username = map.get("user_id").toString();
        } else {
            this.username = "UNKNOWN_USER";
        }
        if (map.containsKey("email") && map.containsKey("email_verified")) {
            this.emailVerified = Boolean.valueOf(map.get("email_verified").toString());
        }
        setupGrantedAuthorities(map, authorityStrategy);
    }

    private void setupGrantedAuthorities(final Map<String, Object> map, final AuthorityStrategy authorityStrategy) {
        this.authorities = new ArrayList<>();
        try {
            final Collection<String> authorities = authorityStrategy.getAuthorities(map);
            if (authorities != null) {
                 for (final String authority : authorities) {
                    this.authorities.add(new SimpleGrantedAuthority(authority));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /**
     * Will return UnsupportedOperationException
     */
    public String getPassword() {
        throw new UnsupportedOperationException("Password is protected");
    }

    /**
     * Gets the email if it exists otherwise it returns the user_id
     */
    public String getUsername() {
        return username;
    }

    public boolean isAccountNonExpired() {
        return false;
    }

    public boolean isAccountNonLocked() {
        return false;
    }

    public boolean isCredentialsNonExpired() {
        return false;
    }

    /**
     * Will return true if the email is verified, otherwise it will return false
     */
    public boolean isEnabled() {
        return emailVerified;
    }

    /**
     * Will return the details of the attribute of JWT decoded token if it exists or null otherwise.
     * Example getAuth0Attribute("email"), getAuth0Attribute("picture")....
     *
     * @return return the details of the JWT decoded token if it exists  or null otherwise
     */
    public Object getAuth0Attribute(String attributeName) {
        return details.get(attributeName);
    }


}
