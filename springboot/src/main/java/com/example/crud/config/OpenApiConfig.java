package com.example.crud.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.Scopes;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI document for the product API.
 *
 * Every operation requires a token, so both token flows served by
 * {@link AuthorizationServerConfig} are declared: "password" for a real user's
 * credentials and "clientCredentials" for machine to machine calls. Swagger
 * UI's Authorize button fetches the token and sends it on every try-it-out
 * request.
 */
@Configuration
public class OpenApiConfig {

    private static final String SECURITY_SCHEME = "oauth2";
    private static final String TOKEN_URL = "/oauth2/token";

    @Bean
    public OpenAPI productApi() {
        OAuthFlows flows = new OAuthFlows()
                .password(new OAuthFlow().tokenUrl(TOKEN_URL).scopes(scopes()))
                .clientCredentials(new OAuthFlow().tokenUrl(TOKEN_URL).scopes(scopes()));

        SecurityScheme oauth2 = new SecurityScheme()
                .type(SecurityScheme.Type.OAUTH2)
                .description("Authenticate first: Authorize, pick the password flow, and sign in as a user "
                        + "(alice/alice-secret has read and write, bob/bob-secret is read only).")
                .flows(flows);

        return new OpenAPI()
                .info(new Info()
                        .title("CRUD Service API")
                        .version("v1")
                        .description("REST CRUD API for products. Every operation needs a bearer token from "
                                + TOKEN_URL + "."))
                .components(new Components().addSecuritySchemes(SECURITY_SCHEME, oauth2))
                .addSecurityItem(new SecurityRequirement().addList(SECURITY_SCHEME));
    }

    private Scopes scopes() {
        return new Scopes()
                .addString("products.read", "Read products")
                .addString("products.write", "Create, update and delete products");
    }
}
