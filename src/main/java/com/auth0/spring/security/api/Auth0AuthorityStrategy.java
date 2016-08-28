package com.auth0.spring.security.api;


import com.auth0.spring.security.api.authority.AuthorityStrategy;
import com.auth0.spring.security.api.authority.ListAttributeStrategy;
import com.auth0.spring.security.api.authority.StringAttributeStrategy;

/**
 * The authority strategy being used
 *
 * Three possible types of strategy pertaining to "Role" info are built in:
 * Groups, Roles, and Scope
 *
 * For API Resource Server using JWT Tokens - `scope` is the default
 *
 */
public enum Auth0AuthorityStrategy {

    GROUPS("groups", new ListAttributeStrategy("groups")),
    ROLES("roles", new ListAttributeStrategy("roles")),
    SCOPE("scope", new StringAttributeStrategy("scope"));

    private final String name;
    private final AuthorityStrategy strategy;

    Auth0AuthorityStrategy(final String name, final AuthorityStrategy strategy) {
        this.name = name;
        this.strategy = strategy;
    }

    public AuthorityStrategy getStrategy() {
      return this.strategy;
    }

    @Override
    public String toString() {
        return this.name;
    }

    public static boolean contains(String value) {
        for (final Auth0AuthorityStrategy authorityStrategy : values()) {
            if (authorityStrategy.name().equals(value)) {
                return true;
            }
        }
        return false;
    }

}
