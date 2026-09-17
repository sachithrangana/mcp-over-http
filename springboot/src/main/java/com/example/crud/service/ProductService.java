package com.example.crud.service;

import com.example.crud.exception.ProductNotFoundException;
import com.example.crud.model.Product;
import com.example.crud.repository.ProductRepository;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class ProductService {

    private final ProductRepository repository;

    public ProductService(ProductRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public List<Product> findAll() {
        return repository.findAll();
    }

    @Transactional(readOnly = true)
    public Product findById(Long id) {
        return repository.findById(id).orElseThrow(() -> new ProductNotFoundException(id));
    }

    public Product create(Product product) {
        return repository.save(product);
    }

    public Product update(Long id, Product changes) {
        Product existing = findById(id);
        existing.setName(changes.getName());
        existing.setDescription(changes.getDescription());
        existing.setPrice(changes.getPrice());
        return existing;
    }

    public void delete(Long id) {
        if (!repository.existsById(id)) {
            throw new ProductNotFoundException(id);
        }
        repository.deleteById(id);
    }
}
