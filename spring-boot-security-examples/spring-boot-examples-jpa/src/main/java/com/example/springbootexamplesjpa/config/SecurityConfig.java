/*
 *  Copyright (c) 2023 DMG
 *  All Rights Reserved Worldwide.
 *
 *  THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO DMG
 *  AND CONSTITUTES A VALUABLE TRADE SECRET.
 */

package com.example.springbootexamplesjpa.config;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Piyush Kumar.
 * @since 16/09/23.
 */

@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfig {


//    /**
//     * Configuring WebSecurityConfigurerAdapter is deprecated.
//     * <a href="https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter">check this</a>
//     */
//    @AllArgsConstructor
//    @Configuration
//    public static class ConfigUsingWebSecurityConfigurer extends WebSecurityConfigurerAdapter {
//
//        private final UserDetailsService userDetailsService;
//
//        @Override
//        public void configure(AuthenticationManagerBuilder auth) throws Exception {
//
//            auth.authenticationProvider(authenticationProvider());
//        }
//
//        @Override
//        public void configure(HttpSecurity http) throws Exception {
//
//            http.csrf().disable();
//            http
//                .authorizeRequests()
//                .antMatchers("/users/authenticatedUsr/**").authenticated()
//                .antMatchers("/users/adm/**").hasRole("ADMIN")
//                .antMatchers("/users/usr/**").hasAnyRole("ADMIN", "USER")
//                .antMatchers("/checkAuthorities/admUsr").hasAuthority("DELETE")
//                .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
//                .and()
//                .authorizeRequests()
//                .antMatchers("/users/create/**").permitAll()
//                .and()
//                .authorizeRequests().anyRequest().authenticated()
//                .and()
//                .httpBasic();
//        }
//
//        @Bean
//        public AuthenticationProvider authenticationProvider(){
//            DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
//            authenticationProvider.setUserDetailsService(userDetailsService);
//            authenticationProvider.setPasswordEncoder(passwordEncoder());
//            return authenticationProvider;
//        }
//
//        @Bean
//        public PasswordEncoder passwordEncoder(){
//            return new BCryptPasswordEncoder();
//        }
//    }


    @Configuration
    @AllArgsConstructor
    public static class ConfigUsingSecurityFilterChain {

        private final UserDetailsService userDetailsService;

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

            /* You can configure HttpSecurity in following two ways */

            /* Without using lambdas */
//            http.csrf().disable();
//
//            return http
//                .authorizeRequests()
//                .antMatchers("/users/authenticatedUsr/**").authenticated()
//                .antMatchers("/users/adm/**").hasRole("ADMIN")
//                .antMatchers("/users/usr/**").hasAnyRole("ADMIN", "USER")
//                .antMatchers("/checkAuthorities/admUsr").hasAuthority("DELETE")
//                .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
//                .and()
//                .authorizeRequests()
//                .antMatchers("/users/create/**").permitAll()
//                .and()
//                .authorizeRequests().anyRequest().authenticated()
//                .and()
//                .httpBasic()
//                .and()
//                .build();

            /* With using lamdas */
            http.csrf(csrf -> csrf.disable());
            return http.authorizeRequests(auth -> {
                    auth.antMatchers("/users/authenticatedUsr/**").authenticated()
                        .antMatchers("/users/adm/**").hasRole("ADMIN")
                        .antMatchers("/users/usr/**").hasAnyRole("ADMIN", "USER")
                        .antMatchers("/checkAuthorities/admUsr").hasAuthority("DELETE")
                        .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
                        .antMatchers("/users/create/**").permitAll()
                        .anyRequest().authenticated();
                })
                .userDetailsService(userDetailsService)
//                .authenticationProvider() // we could also use this and assign a authentication provider bean as we did above.
                .httpBasic(Customizer.withDefaults())
                .build();


        }

        @Bean
        public PasswordEncoder passwordEncoder () {
            return new BCryptPasswordEncoder();
        }

    }
}
