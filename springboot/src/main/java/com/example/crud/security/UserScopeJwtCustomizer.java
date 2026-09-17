package com.example.crud.security;

import com.example.crud.repository.AppUserRepository;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Caps every user token at the scopes that user is actually allowed to hold.
 *
 * The consent screen already offers only the permitted scopes, but that is a UI
 * filter and a UI filter is not a security control: a hand-crafted POST to
 * /oauth2/authorize could approve any scope the client is registered for. This
 * runs at the last point that matters — the resource server authorizes purely on
 * the JWT's scope claim (see SecurityConfig), so intersecting the claim with the
 * user's allowance here means a forged consent cannot widen access. bob consents
 * to products.write somehow, his token still comes back read only.
 *
 * Client credentials tokens have no user behind them, so they are left alone.
 */
@Component
public class UserScopeJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final AppUserRepository repository;

    public UserScopeJwtCustomizer(AppUserRepository repository) {
        this.repository = repository;
    }

    @Override
    @Transactional(readOnly = true)
    public void customize(JwtEncodingContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return;
        }

        Authentication principal = context.getPrincipal();
        if (principal instanceof OAuth2ClientAuthenticationToken) {
            return;
        }

        repository.findByUsername(principal.getName()).ifPresent(user -> {
            Set<String> granted = new LinkedHashSet<>(context.getAuthorizedScopes());
            granted.retainAll(user.scopeSet());
            context.getClaims().claim("scope", granted);
        });
    }
}
