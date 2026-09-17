package com.example.crud;

import static org.hamcrest.Matchers.is;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class ProductControllerTest {

    @Autowired
    private MockMvc mockMvc;

    private static JwtRequestPostProcessor readWriteToken() {
        return jwt().jwt(builder -> builder.claim("scope", "products.read products.write"));
    }

    @Test
    void fullCrudLifecycle() throws Exception {
        String created = mockMvc.perform(post("/api/products").with(readWriteToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Desk\",\"description\":\"Standing desk\",\"price\":499.00}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name", is("Desk")))
                .andReturn().getResponse().getContentAsString();

        String id = created.replaceAll(".*\"id\":(\\d+).*", "$1");

        mockMvc.perform(get("/api/products/" + id).with(readWriteToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.price", is(499.00)));

        mockMvc.perform(put("/api/products/" + id).with(readWriteToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Desk XL\",\"description\":\"Wider\",\"price\":599.00}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name", is("Desk XL")));

        mockMvc.perform(delete("/api/products/" + id).with(readWriteToken()))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/api/products/" + id).with(readWriteToken()))
                .andExpect(status().isNotFound());
    }

    @Test
    void rejectsInvalidPayload() throws Exception {
        mockMvc.perform(post("/api/products").with(readWriteToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"\",\"price\":-5}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.name").exists())
                .andExpect(jsonPath("$.errors.price").exists());
    }

    @Test
    void healthEndpointReportsUp() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("UP")))
                .andExpect(jsonPath("$.components.db.status", is("UP")));
    }
}
