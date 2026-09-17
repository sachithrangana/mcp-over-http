package com.example.crud;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Test
    void issuesAccessTokenForValidClientCredentials() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic("crud-client", "crud-secret"))
                        .param("grant_type", "client_credentials")
                        .param("scope", "products.read products.write"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.token_type", is("Bearer")))
                .andExpect(jsonPath("$.scope", containsString("products.read")));
    }

    @Test
    void rejectsBadClientSecret() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic("crud-client", "wrong-secret"))
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsApiCallWithoutToken() throws Exception {
        mockMvc.perform(get("/api/products")).andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/products")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Nope\",\"price\":1}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void readScopeCannotWrite() throws Exception {
        var readOnly = jwt().jwt(builder -> builder.claim("scope", "products.read"));

        mockMvc.perform(get("/api/products").with(readOnly)).andExpect(status().isOk());

        mockMvc.perform(post("/api/products").with(readOnly)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Nope\",\"price\":1}"))
                .andExpect(status().isForbidden());

        mockMvc.perform(delete("/api/products/1").with(readOnly)).andExpect(status().isForbidden());
    }

    @Test
    void issuesAccessTokenForUserCredentials() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic("crud-client", "crud-secret"))
                        .param("grant_type", "password")
                        .param("username", "alice")
                        .param("password", "alice-secret")
                        .param("scope", "products.read products.write"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.token_type", is("Bearer")))
                .andExpect(jsonPath("$.scope", containsString("products.write")));
    }

    /** The token identifies the user, not the client. */
    @Test
    void userTokenCarriesUsernameAsSubject() throws Exception {
        String body = mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic("crud-client", "crud-secret"))
                        .param("grant_type", "password")
                        .param("username", "alice")
                        .param("password", "alice-secret"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String token = JsonPath.read(body, "$.access_token");
        assertThat(jwtDecoder.decode(token).getSubject()).isEqualTo("alice");
    }

    @Test
    void rejectsWrongUserPassword() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic("crud-client", "crud-secret"))
                        .param("grant_type", "password")
                        .param("username", "alice")
                        .param("password", "not-her-password"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", is("invalid_grant")));
    }

    /** bob is seeded read only, so he cannot obtain a write token. */
    @Test
    void rejectsScopeTheUserMayNotHold() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic("crud-client", "crud-secret"))
                        .param("grant_type", "password")
                        .param("username", "bob")
                        .param("password", "bob-secret")
                        .param("scope", "products.write"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", is("invalid_scope")));
    }

    /** End to end: a user token actually opens the products API. */
    @Test
    void userTokenIsAcceptedByTheProductApi() throws Exception {
        String body = mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic("crud-client", "crud-secret"))
                        .param("grant_type", "password")
                        .param("username", "alice")
                        .param("password", "alice-secret")
                        .param("scope", "products.read products.write"))
                .andReturn().getResponse().getContentAsString();

        String token = JsonPath.read(body, "$.access_token");

        mockMvc.perform(get("/api/products").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/products").header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"From alice\",\"price\":12.50}"))
                .andExpect(status().isCreated());
    }

    @Test
    void discoveryAndJwksAreAvailable() throws Exception {
        mockMvc.perform(get("/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_endpoint").exists());

        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty", is("RSA")));
    }
}
