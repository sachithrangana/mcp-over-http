package com.example.crud.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The browser half of authentication: the login form and the consent screen that
 * the authorization code flow sends the user through.
 *
 * It sits between the authorization server chain and the API chain. The API chain
 * is stateless and bearer token only, which is right for /api/** but cannot log
 * anybody in, so these two paths need their own session backed, form based chain.
 *
 * Only /login and /oauth2/consent are matched — everything else still falls
 * through to SecurityConfig.
 */
@Configuration
public class LoginSecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain loginFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/login", "/logout", "/oauth2/consent", "/css/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/css/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll())
                .logout(logout -> logout.logoutSuccessUrl("/login?logout"));

        return http.build();
    }
}
