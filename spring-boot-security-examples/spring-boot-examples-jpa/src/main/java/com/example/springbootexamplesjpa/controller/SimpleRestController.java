/*
 *  Copyright (c) 2023 DMG
 *  All Rights Reserved Worldwide.
 *
 *  THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO DMG
 *  AND CONSTITUTES A VALUABLE TRADE SECRET.
 */

package com.example.springbootexamplesjpa.controller;

import com.example.springbootexamplesjpa.domain.entity.User;
import com.example.springbootexamplesjpa.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Piyush Kumar.
 * @since 16/09/23.
 */

@AllArgsConstructor
@RestController
public class SimpleRestController {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    // region check basic authentication based on roles

    @PostMapping("/users/create")
    public void addUser(@RequestBody User user){

        user.setActive(true);
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        userRepository.save(user);
    }

    @GetMapping("/users/authenticatedUsr")
    public ResponseEntity<Object> getAuthenticatedUsers(){


        return ResponseEntity.ok(userRepository.findAll());
    }

    @GetMapping("/users/adm")
    public ResponseEntity<Object> getAdminUsers(){

        return ResponseEntity.ok(userRepository.findAll());
    }


    @GetMapping("/users/usr")
    public ResponseEntity<Object> getUsersForUsrRole(){

        return ResponseEntity.ok(userRepository.findAll());
    }


    @GetMapping("/checkAuthorities/admUsr")
    public ResponseEntity<Object> getUsersByAdmAuth(){

        return ResponseEntity.ok(userRepository.findAll());
    }


    @GetMapping("/checkAuthorities/usr")
    public ResponseEntity<Object> getUsersByUserAuth(){

        return ResponseEntity.ok(userRepository.findAll());
    }

    // endregion check basic authentication based on roles


}
