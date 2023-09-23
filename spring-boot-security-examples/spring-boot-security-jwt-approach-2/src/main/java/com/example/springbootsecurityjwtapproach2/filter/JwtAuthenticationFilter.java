/*
 *  Copyright (c) 2023 DMG
 *  All Rights Reserved Worldwide.
 *
 *  THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO DMG
 *  AND CONSTITUTES A VALUABLE TRADE SECRET.
 */

package com.example.springbootsecurityjwtapproach2.filter;

import com.example.springbootsecurityjwtapproach2.domain.AuthRequest;
import com.example.springbootsecurityjwtapproach2.domain.AuthResponse;
import com.example.springbootsecurityjwtapproach2.util.JwtUtil;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

/**
 * @author Piyush Kumar.
 * @since 23/09/23.
 */
@Component
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final ObjectMapper objectMapper;
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    public JwtAuthenticationFilter(final ObjectMapper objectMapper,
                                   final JwtUtil jwtUtil,
                                   final UserDetailsService userDetailsService,
                                   final AuthenticationManager authenticationManager){

        super(authenticationManager);

        this.objectMapper = objectMapper;
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        AuthRequest authRequest = null;
        try {
            authRequest = objectMapper.readValue(request.getInputStream(), AuthRequest.class);

        }catch (IOException e){
            e.printStackTrace();
        }

        String username = authRequest.getUsername();
        String password = authRequest.getPassword();


        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.unauthenticated(username, password);

        return this.getAuthenticationManager().authenticate(authentication);
    }


    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {


        UserDetails userDetails = userDetailsService.loadUserByUsername(authResult.getName());

        String jwtToken = jwtUtil.generateToken(userDetails);

        /* Setting JWT token in header. */
        response.addHeader("Authorization", "Bearer " + jwtToken);

        /* Setting JWT token in body. */
        PrintWriter out = response.getWriter();
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
        out.print(objectMapper.writeValueAsString(AuthResponse.builder().accessToken(jwtToken)));
//        out.write(objectMapper.writeValueAsString(AuthResponse.builder().accessToken(jwtToken))); // we can use write as well.
        out.flush();



        UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken) authResult;
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);

//        SecurityContext context = SecurityContextHolder.createEmptyContext();
//        context.setAuthentication(authentication);
//        SecurityContextHolder.setContext(context);
    }



}
