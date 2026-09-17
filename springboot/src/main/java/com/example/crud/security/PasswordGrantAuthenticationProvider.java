package com.example.crud.security;

import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * Authenticates the end user's username and password, then issues an access
 * token for the scopes allowed by the client, the user, and the request.
 *
 * The password grant is not part of OAuth 2.1 and Spring Authorization Server
 * ships no implementation of it, so this class supplies one. It mirrors the
 * built-in client_credentials provider: validate client, validate scopes,
 * generate a token, save the authorization.
 */
public final class PasswordGrantAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final AuthenticationManager userAuthenticationManager;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    public PasswordGrantAuthenticationProvider(AuthenticationManager userAuthenticationManager,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        this.userAuthenticationManager = userAuthenticationManager;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PasswordGrantAuthenticationToken passwordGrant = (PasswordGrantAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal = clientPrincipal(passwordGrant);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (registeredClient == null
                || !registeredClient.getAuthorizationGrantTypes().contains(PasswordGrantAuthenticationToken.GRANT_TYPE)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        Authentication user = authenticateUser(passwordGrant);
        Set<String> authorizedScopes = authorizedScopes(passwordGrant, registeredClient, user);

        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(user)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(PasswordGrantAuthenticationToken.GRANT_TYPE)
                .authorizationGrant(passwordGrant)
                .build();

        OAuth2Token generated = tokenGenerator.generate(tokenContext);
        if (generated == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", ERROR_URI));
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generated.getTokenValue(), generated.getIssuedAt(), generated.getExpiresAt(), authorizedScopes);

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(user.getName())
                .authorizationGrantType(PasswordGrantAuthenticationToken.GRANT_TYPE)
                .authorizedScopes(authorizedScopes)
                .attribute(Principal.class.getName(), user);

        if (generated instanceof ClaimAccessor claimAccessor) {
            authorizationBuilder.token(accessToken,
                    metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        authorizationService.save(authorizationBuilder.build());

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private OAuth2ClientAuthenticationToken clientPrincipal(PasswordGrantAuthenticationToken passwordGrant) {
        if (passwordGrant.getPrincipal() instanceof OAuth2ClientAuthenticationToken client
                && client.isAuthenticated()) {
            return client;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    /**
     * Wrong username or password must surface as invalid_grant, not as a raw
     * authentication failure, so the response stays a valid OAuth2 error body.
     */
    private Authentication authenticateUser(PasswordGrantAuthenticationToken passwordGrant) {
        try {
            return userAuthenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(passwordGrant.getUsername(), passwordGrant.getPassword()));
        } catch (AuthenticationException ex) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
                    "Bad username or password.", ERROR_URI));
        }
    }

    /**
     * A token may only carry scopes the client is registered for and the user is
     * allowed to hold. An empty request means "everything the user may have".
     */
    private Set<String> authorizedScopes(PasswordGrantAuthenticationToken passwordGrant,
            RegisteredClient registeredClient, Authentication user) {

        Set<String> userScopes = new LinkedHashSet<>();
        for (GrantedAuthority authority : user.getAuthorities()) {
            if (authority.getAuthority().startsWith("SCOPE_")) {
                userScopes.add(authority.getAuthority().substring("SCOPE_".length()));
            }
        }
        userScopes.retainAll(registeredClient.getScopes());

        Set<String> requested = passwordGrant.getScopes();
        if (requested.isEmpty()) {
            return userScopes;
        }

        for (String scope : requested) {
            if (!userScopes.contains(scope)) {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE,
                        "Scope not permitted for this user or client: " + scope, ERROR_URI));
            }
        }
        return new LinkedHashSet<>(requested);
    }
}
