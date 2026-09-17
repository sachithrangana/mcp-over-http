package com.example.crud.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Resource server rules for the product API: every /api/** call needs a valid
 * bearer token, with reads requiring the products.read scope and writes
 * products.write. Get a token from /oauth2/token first, using either the
 * password grant (a user's own credentials) or client_credentials.
 *
 * Health, info, the OpenAPI document and Swagger UI stay open so probes work
 * and the docs page can load before the user authorizes.
 *
 * Scope claims arrive as SCOPE_* authorities via Spring Security's default
 * JWT converter, so no custom converter is needed.
 */
@Configuration
public class SecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll()
                        .requestMatchers("/v3/api-docs", "/v3/api-docs.yaml", "/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/**").hasAuthority("SCOPE_products.read")
                        .requestMatchers(HttpMethod.POST, "/api/**").hasAuthority("SCOPE_products.write")
                        .requestMatchers(HttpMethod.PUT, "/api/**").hasAuthority("SCOPE_products.write")
                        .requestMatchers(HttpMethod.DELETE, "/api/**").hasAuthority("SCOPE_products.write")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
