package com.auth0.spring.security.api;

/**
 * The authority strategy being used
 *
 * Would expect three possible types of strategy pertaining to "Role" info:
 * Groups, Roles, and Scope
 *
 * For API Resource Server using JWT Tokens - `scope` is the default
 * Configurable via auth0.properties file
 *
 */
public enum Auth0AuthorityStrategy {

    GROUPS("groups"),
    ROLES("roles"),
    SCOPE("scope");

    private final String name;

    private Auth0AuthorityStrategy(final String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return this.name;
    }

    public static boolean contains(String value) {
        for (final Auth0AuthorityStrategy authorityStrategy : Auth0AuthorityStrategy.values()) {
            if (authorityStrategy.name().equals(value)) {
                return true;
            }
        }
        return false;
    }

}
