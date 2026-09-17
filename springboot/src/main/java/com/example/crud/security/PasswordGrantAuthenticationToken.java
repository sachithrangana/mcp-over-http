package com.example.crud.security;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

/**
 * Token endpoint request for the custom password grant: the authenticated
 * client plus the end user's credentials and requested scopes.
 */
public class PasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    public static final AuthorizationGrantType GRANT_TYPE = new AuthorizationGrantType("password");

    private final String username;
    private final String password;
    private final Set<String> scopes;

    public PasswordGrantAuthenticationToken(String username, String password, Set<String> scopes,
            Authentication clientPrincipal, Map<String, Object> additionalParameters) {
        super(GRANT_TYPE, clientPrincipal, additionalParameters);
        this.username = username;
        this.password = password;
        this.scopes = Collections.unmodifiableSet(scopes);
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
