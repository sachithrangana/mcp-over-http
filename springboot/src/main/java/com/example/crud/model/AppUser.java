package com.example.crud.model;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A user that can exchange their credentials for an access token via the
 * password grant. Table is app_user because USER is reserved in H2.
 */
@Entity
@Table(name = "app_user")
@Schema(hidden = true)
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    /** BCrypt hash, never the plaintext password. */
    @Column(nullable = false)
    private String password;

    /**
     * Scopes this user may request, comma separated. A token is issued with the
     * intersection of these, the client's scopes, and what was requested.
     */
    @Column(nullable = false)
    private String scopes;

    @Column(nullable = false)
    private boolean enabled = true;

    protected AppUser() {
    }

    public AppUser(String username, String password, String scopes) {
        this.username = username;
        this.password = password;
        this.scopes = scopes;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Set<String> scopeSet() {
        Set<String> result = new LinkedHashSet<>();
        for (String scope : scopes.split(",")) {
            String trimmed = scope.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }
}
