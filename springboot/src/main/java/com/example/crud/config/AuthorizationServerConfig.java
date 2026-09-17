package com.example.crud.config;

import com.example.crud.security.PasswordGrantAuthenticationConverter;
import com.example.crud.security.PasswordGrantAuthenticationProvider;
import com.example.crud.security.PasswordGrantAuthenticationToken;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;

/**
 * Self-contained OAuth2 authorization server: issues JWT access tokens at
 * /oauth2/token using either the client_credentials grant (machine to machine)
 * or the custom password grant (a real user's username and password, see
 * {@link PasswordGrantAuthenticationProvider}). The same application validates
 * those tokens as a resource server (see {@link SecurityConfig}).
 */
@Configuration
public class AuthorizationServerConfig {

    /** Served by AuthUiController; not an authorization server endpoint itself. */
    static final String CONSENT_PAGE = "/oauth2/consent";

    private final String remoteClientId;

    public AuthorizationServerConfig(
            @Value("${crud.mcp.remote-client-id:crud-mcp-remote}") String remoteClientId) {
        this.remoteClientId = remoteClientId;
    }

    /**
     * The MCP plugin is a native app: it cannot keep a secret and it listens on a
     * loopback port for the redirect. RFC 8252 asks servers to allow any port on
     * 127.0.0.1, but Spring matches redirect URIs exactly, so a small fixed range
     * is registered and the plugin binds the first one that is free.
     */
    /** Ports Claude Code may be told to listen on with --callback-port. */
    static final List<Integer> CLAUDE_CALLBACK_PORTS = List.of(8765, 8766, 8767, 8768, 8769);

    static final List<String> PLUGIN_REDIRECT_URIS = List.of(
            "http://127.0.0.1:8765/callback",
            "http://127.0.0.1:8766/callback",
            "http://127.0.0.1:8767/callback",
            "http://127.0.0.1:8768/callback",
            "http://127.0.0.1:8769/callback");

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerFilterChain(HttpSecurity http,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator,
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
                        .consentPage(CONSENT_PAGE))
                .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .accessTokenRequestConverter(new PasswordGrantAuthenticationConverter())
                        .authenticationProvider(new PasswordGrantAuthenticationProvider(
                                userAuthenticationManager(userDetailsService, passwordEncoder),
                                authorizationService,
                                tokenGenerator)));

        // A browser arriving at /oauth2/authorize without a session must be sent to
        // the login form; API style clients still get a 401 rather than an HTML page.
        http.exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));

        http.oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
        return http.build();
    }

    /**
     * Authenticates end users for the password grant. Kept separate from the
     * filter chain's own AuthenticationManager so it only ever sees username and
     * password requests.
     */
    private AuthenticationManager userAuthenticationManager(UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    /**
     * Explicit generator so the custom password grant and the built-in grants
     * mint identical JWTs.
     */
    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource,
            List<OAuth2TokenCustomizer<JwtEncodingContext>> jwtCustomizers) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        // Each customizer owns one concern (scope ceiling, audience); they compose in order.
        jwtGenerator.setJwtCustomizer(context -> jwtCustomizers.forEach(c -> c.customize(context)));
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, new OAuth2AccessTokenGenerator());
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        return new InMemoryRegisteredClientRepository(
                serviceClient(passwordEncoder), pluginClient(), remoteMcpClient());
    }

    /**
     * The client Claude Code uses for the deployed MCP server.
     *
     * Claude Code prefers dynamic client registration, but Spring's registration
     * endpoint needs an initial access token that Claude Code has no way to hold,
     * so this is pre-registered instead and the user passes --client-id. Public and
     * PKCE bound for the same reason as the local plugin. The redirect URIs are
     * localhost callbacks because the browser runs on the user's machine even when
     * the MCP server does not; the port is chosen with --callback-port.
     */
    private RegisteredClient remoteMcpClient() {
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(remoteClientId)
                .clientName("CRUD Products remote MCP server")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("products.read")
                .scope("products.write")
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofHours(8))
                        .build());

        CLAUDE_CALLBACK_PORTS.forEach(port ->
                builder.redirectUri("http://localhost:" + port + "/callback"));
        return builder.build();
    }

    /**
     * The MCP plugin's client. Public (no secret, PKCE mandatory) because it runs
     * on the user's machine, where any embedded secret is readable. Consent is
     * required so read and write are granted per login rather than implied.
     *
     * No refresh token: Spring Authorization Server only issues one to a client
     * that authenticates, and this client authenticates with NONE. Rather than
     * give it a secret it cannot keep, the access token simply lives a working
     * day, after which the login tool runs the browser flow again. The
     * refresh_token grant stays registered so that making this client
     * confidential later is a one line change.
     */
    private RegisteredClient pluginClient() {
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("crud-plugin")
                .clientName("CRUD Products MCP plugin")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("products.read")
                .scope("products.write")
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofHours(8))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false)
                        .build());

        PLUGIN_REDIRECT_URIS.forEach(builder::redirectUri);
        return builder.build();
    }

    /** Machine to machine client: client_credentials plus the legacy password grant. */
    private RegisteredClient serviceClient(PasswordEncoder passwordEncoder) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("crud-client")
                .clientSecret(passwordEncoder.encode("crud-secret"))
                .clientAuthenticationMethods(methods -> {
                    methods.add(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                    methods.add(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_POST);
                })
                .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(PasswordGrantAuthenticationToken.GRANT_TYPE)
                .scope("products.read")
                .scope("products.write")
                .clientSettings(ClientSettings.builder().requireProofKey(false).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(1)).build())
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * Signing key generated at startup. Fine for a demo; tokens are invalidated by a
     * restart. A real deployment loads a persistent key from a keystore or secret manager.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        RSAKey key = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();

        return new ImmutableJWKSet<>(new JWKSet(key));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * The issuer must be the URL clients actually reach, because it goes into every
     * token's `iss` and into the discovery document. Left unset, Spring derives it
     * from the incoming request, which is right locally but wrong behind a proxy or
     * in a container; a deployment sets crud.issuer-url to its public URL.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings(
            @Value("${crud.issuer-url:}") String issuerUrl) {
        AuthorizationServerSettings.Builder builder = AuthorizationServerSettings.builder();
        if (!issuerUrl.isBlank()) {
            builder.issuer(issuerUrl);
        }
        return builder.build();
    }
}
