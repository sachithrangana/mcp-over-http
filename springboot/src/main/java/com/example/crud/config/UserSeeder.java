package com.example.crud.config;

import com.example.crud.model.AppUser;
import com.example.crud.repository.AppUserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Seeds demo users into the in-memory database on startup. Real deployments
 * manage users elsewhere; these exist so the password grant is usable
 * immediately after a clean start.
 */
@Configuration
public class UserSeeder {

    @Bean
    public CommandLineRunner seedUsers(AppUserRepository repository, PasswordEncoder passwordEncoder) {
        return args -> {
            seed(repository, passwordEncoder, "alice", "alice-secret", "products.read,products.write");
            seed(repository, passwordEncoder, "bob", "bob-secret", "products.read");
        };
    }

    private void seed(AppUserRepository repository, PasswordEncoder encoder, String username, String password, String scopes) {
        if (repository.findByUsername(username).isEmpty()) {
            repository.save(new AppUser(username, encoder.encode(password), scopes));
        }
    }
}
