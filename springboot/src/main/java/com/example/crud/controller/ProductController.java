package com.example.crud.controller;

import com.example.crud.model.Product;
import com.example.crud.service.ProductService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.net.URI;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/products")
@Tag(name = "Products", description = "CRUD operations on products")
public class ProductController {

    private final ProductService service;

    public ProductController(ProductService service) {
        this.service = service;
    }

    @GetMapping
    @Operation(summary = "List all products", description = "Requires a bearer token with the products.read scope.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Products returned"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid bearer token", content = @Content),
            @ApiResponse(responseCode = "403", description = "Token lacks the products.read scope", content = @Content)
    })
    public List<Product> list() {
        return service.findAll();
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get one product by id", description = "Requires a bearer token with the products.read scope.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Product found"),
            @ApiResponse(responseCode = "404", description = "No product with that id"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid bearer token", content = @Content),
            @ApiResponse(responseCode = "403", description = "Token lacks the products.read scope", content = @Content)
    })
    public Product get(@PathVariable Long id) {
        return service.findById(id);
    }

    @PostMapping
    @Operation(summary = "Create a product", description = "Requires a bearer token with the products.write scope.")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Product created"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid bearer token", content = @Content),
            @ApiResponse(responseCode = "403", description = "Token lacks the products.write scope", content = @Content)
    })
    public ResponseEntity<Product> create(@Valid @RequestBody Product product) {
        Product saved = service.create(product);
        return ResponseEntity.created(URI.create("/api/products/" + saved.getId())).body(saved);
    }

    @PutMapping("/{id}")
    @Operation(summary = "Replace a product", description = "Requires a bearer token with the products.write scope.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Product replaced"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "404", description = "No product with that id"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid bearer token", content = @Content),
            @ApiResponse(responseCode = "403", description = "Token lacks the products.write scope", content = @Content)
    })
    public Product update(@PathVariable Long id, @Valid @RequestBody Product product) {
        return service.update(id, product);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete a product", description = "Requires a bearer token with the products.write scope.")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Product deleted"),
            @ApiResponse(responseCode = "404", description = "No product with that id"),
            @ApiResponse(responseCode = "401", description = "Missing or invalid bearer token", content = @Content),
            @ApiResponse(responseCode = "403", description = "Token lacks the products.write scope", content = @Content)
    })
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }
}
