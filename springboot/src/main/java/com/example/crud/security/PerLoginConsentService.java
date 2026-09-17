package com.example.crud.security;

import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Component;

/**
 * Deliberately forgets consent, so the consent screen appears on every login.
 *
 * Spring's default service remembers what a user approved and silently reuses it,
 * which would mean alice ticks products.write once and every later login carries
 * write access without asking. Granting write is meant to be a per login decision
 * here, so nothing is stored and the question is asked each time.
 *
 * The cost is that a user cannot "remember this choice"; the refresh token is what
 * keeps them from re-authorizing constantly, not a remembered consent.
 */
@Component
public class PerLoginConsentService implements OAuth2AuthorizationConsentService {

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        // Intentionally not stored; see the class javadoc.
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        // Nothing is ever stored, so there is nothing to remove.
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        return null;
    }
}
