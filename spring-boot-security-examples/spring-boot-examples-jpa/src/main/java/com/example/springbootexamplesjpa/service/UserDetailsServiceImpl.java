/*
 *  Copyright (c) 2023 DMG
 *  All Rights Reserved Worldwide.
 *
 *  THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO DMG
 *  AND CONSTITUTES A VALUABLE TRADE SECRET.
 */

package com.example.springbootexamplesjpa.service;

import com.example.springbootexamplesjpa.domain.entity.User;
import com.example.springbootexamplesjpa.domain.value.UserPrincipal;
import com.example.springbootexamplesjpa.repository.UserRepository;
import lombok.Data;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author Piyush Kumar.
 * @since 16/09/23.
 */
@Service
@Data
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String emailId) throws UsernameNotFoundException {

        User user = userRepository.getUserByEmailId(emailId);

        return new UserPrincipal(user);
    }
}
