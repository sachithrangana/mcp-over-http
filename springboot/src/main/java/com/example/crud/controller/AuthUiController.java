package com.example.crud.controller;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * The two pages a user sees while authorizing the MCP plugin: the login form and
 * the consent screen.
 *
 * The consent screen only ever offers scopes the signed in user is allowed to
 * hold, so bob (read only) is never shown a write checkbox. That is presentation,
 * not enforcement — {@link com.example.crud.security.UserScopeJwtCustomizer}
 * is what actually caps the issued token.
 */
@Controller
public class AuthUiController {

    private static final String SCOPE_PREFIX = "SCOPE_";

    private final RegisteredClientRepository registeredClientRepository;

    public AuthUiController(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/oauth2/consent")
    public String consent(Authentication authentication, Model model,
            @RequestParam("client_id") String clientId,
            @RequestParam("scope") String requestedScope,
            @RequestParam("state") String state) {

        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        Set<String> allowed = allowedScopes(authentication);

        List<ScopeChoice> choices = new ArrayList<>();
        for (String scope : requestedScope.split(" ")) {
            String trimmed = scope.trim();
            if (!trimmed.isEmpty() && allowed.contains(trimmed)) {
                choices.add(new ScopeChoice(trimmed, describe(trimmed)));
            }
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", client != null ? client.getClientName() : clientId);
        model.addAttribute("state", state);
        model.addAttribute("scopes", choices);
        model.addAttribute("principalName", authentication.getName());
        return "consent";
    }

    /** The scopes this user may hold, taken from their SCOPE_* authorities. */
    private Set<String> allowedScopes(Authentication authentication) {
        Set<String> scopes = new LinkedHashSet<>();
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            String name = authority.getAuthority();
            if (name.startsWith(SCOPE_PREFIX)) {
                scopes.add(name.substring(SCOPE_PREFIX.length()));
            }
        }
        return scopes;
    }

    private String describe(String scope) {
        return switch (scope) {
            case "products.read" -> "View the product catalogue";
            case "products.write" -> "Create, change and delete products";
            default -> scope;
        };
    }

    /** One checkbox on the consent screen. */
    public record ScopeChoice(String scope, String description) {
    }
}
