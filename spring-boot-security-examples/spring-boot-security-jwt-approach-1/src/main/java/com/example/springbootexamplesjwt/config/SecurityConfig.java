/*
 *  Copyright (c) 2023 DMG
 *  All Rights Reserved Worldwide.
 *
 *  THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO DMG
 *  AND CONSTITUTES A VALUABLE TRADE SECRET.
 */

package com.example.springbootexamplesjwt.config;

import com.example.springbootexamplesjwt.filter.JwtAuthFilter;
import com.example.springbootexamplesjwt.util.JwtUtil;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author Piyush Kumar.
 * @since 16/09/23.
 */
@Data
@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfig {

    /* For jwt with in-memory user we can either create instance of InMemoryUserDetailsManager or we can inject AuthenticationManagerBuilder and get the userDetailsService from it.
     *  Basically, internally it creates the InMemoryUserDetailsManager only check authenticationManagerBuilder.inMemoryAuthentication() implementation.
     * NOTE : below three bean are actually meant for ConfigUsingWebSecurityConfigurer
     * */


    /* Using injection of AuthenticationManagerBuilder */
    @Bean
    public UserDetailsService userDetailsService(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception  {

        /*With in memory user, you can either set roles or authorities but not both at tha same time*/

//        authenticationManagerBuilder.inMemoryAuthentication()
//            .withUser("piyush").password(passwordEncoder().encode("piyush123"))
//            .roles("ADMIN")
////                .authorities("READ", "WRITE", "DELETE")
//            .and()
//            .withUser("sandeep")
//            .password(passwordEncoder().encode("sandeep123"))
//            .roles("USER");
////                .authorities("READ", "WRITE");


        /* If we want to set both we will have to set all authorities and roles within authorities itself */
        authenticationManagerBuilder.inMemoryAuthentication()
            .withUser("piyush").password(passwordEncoder().encode("piyush123"))
            .authorities("ROLE_ADMIN", "READ", "WRITE", "DELETE")
            .and()
            .withUser("sandeep")
            .password(passwordEncoder().encode("sandeep123"))
            .authorities("ROLE_USER", "READ", "WRITE");

        return authenticationManagerBuilder.getDefaultUserDetailsService();
    }

    /* Using creation of instance of InMemoryUserDetailsManager */

    @Bean
    public UserDetailsService userDetailsService() {

        /*With in memory user, you can either set roles or authorities but not both at tha same time*/
        UserDetails user1 = User
            .withUsername("piyush")
            .password(passwordEncoder().encode("piyush123"))
            .authorities("ROLE_ADMIN", "READ", "WRITE", "DELETE")
            .build();

        UserDetails user2 = User
            .withUsername("sandeep")
            .password(passwordEncoder().encode("sandeep123"))
            .authorities("ROLE_USER", "READ", "WRITE")
            .build();

        return new InMemoryUserDetailsManager(user1, user2);
    }



    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    /**
     * Configuring WebSecurityConfigurerAdapter is deprecated.
     * <a href="https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter">check this</a>
     */
    @Data
    @Configuration
    public static class ConfigUsingWebSecurityConfigurer extends WebSecurityConfigurerAdapter {

        private final JwtAuthFilter jwtAuthFilter;

        @Override
        public void configure(HttpSecurity http) throws Exception {

            http.csrf().disable();

            http.authorizeRequests()
                .antMatchers("/authenticate").permitAll()
                .antMatchers("/employee/authenticatedUsr/**").authenticated()
                .antMatchers("/employee/adm/**").hasRole("ADMIN")
                .antMatchers("/employee/usr/**").hasAnyRole("ADMIN", "USER")
                .antMatchers("/checkAuthorities/admUsr").hasAuthority("DELETE")
                .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        }



        @Bean
        public AuthenticationManager authenticationManager() throws Exception   {
            return super.authenticationManager();
        }

//        @Bean
//        public AuthenticationManager authenticationManager(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception   {
//            return authenticationManagerBuilder.build();
//        }
    }


//    @Configuration
//    @AllArgsConstructor
//    public static class ConfigUsingSecurityFilterChain {
//
//
//        @Bean
//        public InMemoryUserDetailsManager userDetailsManager(){
//
//            /* With user details object, implementatio of it is User object - with these you can either set authorities or roles. If you set both the one which
//            * is set later will override the authorities arraylist with the latest one.
//            *
//            * */
////            UserDetails user1 = User
////                .withUsername("piyush")
////                .password(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("piyush123"))
////                .roles("ADMIN")
//////                .authorities("READ", "WRITE", "DELETE")
////                .build();
////
////            UserDetails user2 = User
////                .withUsername("sandeep")
////                .password(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("sandeep123"))
////                .roles("USER")
//////                .authorities("READ", "WRITE")
////                .build();
//
//            /* Either you can do it below.*/
//
////            List<SimpleGrantedAuthority> user1SimpleGrantedAuthorities = List.of(
////                new SimpleGrantedAuthority("ROLE_ADMIN"),
////                new SimpleGrantedAuthority("READ"),
////                new SimpleGrantedAuthority("WRITE"),
////                new SimpleGrantedAuthority("DELETE")
////            );
////            UserDetails user1 = User
////                .withUsername("piyush")
////                .password(passwordEncoder().encode("piyush123"))
////                .authorities(user1SimpleGrantedAuthorities)
////                .build();
////
////            List<SimpleGrantedAuthority> user2SimpleGrantedAuthorities = List.of(
////                new SimpleGrantedAuthority("ROLE_USER"),
////                new SimpleGrantedAuthority("READ"),
////                new SimpleGrantedAuthority("WRITE")
////            );
////
////            UserDetails user2 = User
////                .withUsername("sandeep")
////                .password(passwordEncoder().encode("sandeep123"))
////                .authorities(user2SimpleGrantedAuthorities)
////                .build();
//
//
//            /* OR below but both above and below are eventually setting authorities. */
//
//
//            UserDetails user1 = User
//                .withUsername("piyush")
//                .password(passwordEncoder().encode("piyush123"))
//                .authorities("ROLE_ADMIN", "READ", "WRITE", "DELETE")
//                .build();
//
//            UserDetails user2 = User
//                .withUsername("sandeep")
//                .password(passwordEncoder().encode("sandeep123"))
//                .authorities("ROLE_USER", "READ", "WRITE")
//                .build();
//
//            return new InMemoryUserDetailsManager(user1, user2);
//        }
//
//        @Bean
//        public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthFilter jwtAuthFilter) throws Exception{
//
//            /* You can configure HttpSecurity in following two ways */
//
//            /* Without using lambdas */
//            http.csrf().disable();
//
//            return http
//                .csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/authenticate").permitAll()
//                .antMatchers("/employee/authenticatedUsr/**").authenticated()
//                .antMatchers("/employee/adm/**").hasRole("ADMIN")
//                .antMatchers("/employee/usr/**").hasAnyRole("ADMIN", "USER")
//                .antMatchers("/checkAuthorities/admUsr").hasAuthority("DELETE")
//                .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
//                .and()
//                .sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
//                .build();
//
//
//
////            /* With using lamdas */
////            http.csrf(csrf -> csrf.disable());
////            return http.authorizeRequests(auth -> {
////                    auth.antMatchers("/authenticate").permitAll()
////                        .antMatchers("/employee/authenticatedUsr/**").authenticated()
////                        .antMatchers("/employee/adm/**").hasRole("ADMIN")
////                        .antMatchers("/employee/usr/**").hasAnyRole("ADMIN", "USER")
////                        .antMatchers("/checkAuthorities/admUsr").hasAuthority("DELETE")
////                        .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
////                        .anyRequest().authenticated();
////                })
////                .sessionManagement()
////                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
////                .and()
////                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
////                .build();
//
//        }
//
//        @Bean
//        public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
//            return authConfig.getAuthenticationManager();
//        }
//
//        @Bean
//        public PasswordEncoder passwordEncoder () {
//            return new BCryptPasswordEncoder();
//        }
//
//    }

}
