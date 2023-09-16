/*
 *  Copyright (c) 2023 DMG
 *  All Rights Reserved Worldwide.
 *
 *  THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO DMG
 *  AND CONSTITUTES A VALUABLE TRADE SECRET.
 */

package com.example.springbootsecuritybasic.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author Piyush Kumar.
 * @since 16/09/23.
 */

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    /**
     * Configuring WebSecurityConfigurerAdapter is deprecated.
     * <a href="https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter">check this</a>
     */
    @Configuration
    public static class ConfigUsingWebSecurityConfigurer extends WebSecurityConfigurerAdapter {

        @Override
        public void configure(AuthenticationManagerBuilder auth) throws Exception {

            auth.inMemoryAuthentication()
                .withUser("piyush").password(passwordEncoder().encode("piyush123")).roles("ADMIN").authorities("READ", "WRITE", "DELETE")
                .and()
                .withUser("sandeep").password(passwordEncoder().encode("sandeep123")).roles("USER").authorities("READ", "WRITE");
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {

            http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/employee/authenticatedUsr/**").authenticated()
                .antMatchers("/employee/adm/**").hasRole("ADMIN")
                .antMatchers("/employee/usr/**").hasAnyRole("ADMIN", "USER")
                .antMatchers("/checkAuthorities/admUser").hasAuthority("DELETE")
                .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
                .and()
                .httpBasic();
        }

        @Bean
        public PasswordEncoder passwordEncoder(){
            return new BCryptPasswordEncoder();
        }
    }

}
