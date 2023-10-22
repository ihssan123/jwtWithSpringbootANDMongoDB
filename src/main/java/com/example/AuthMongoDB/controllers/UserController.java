package com.example.AuthMongoDB.controllers;

import com.example.AuthMongoDB.models.User;
import com.example.AuthMongoDB.payload.request.UserRequest;
import com.example.AuthMongoDB.payload.response.UserResponse;
import com.example.AuthMongoDB.repositories.UserRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    UserRepository userRepository;






 @GetMapping("/All")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> getAll() {
        var users=userRepository.findAll();

        return ResponseEntity.ok(users);
    }
}
