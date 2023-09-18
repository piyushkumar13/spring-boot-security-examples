/*
 *  Copyright (c) 2023 DMG
 *  All Rights Reserved Worldwide.
 *
 *  THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO DMG
 *  AND CONSTITUTES A VALUABLE TRADE SECRET.
 */

package com.example.springbootsecuritybasic.config;

import java.util.List;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author Piyush Kumar.
 * @since 16/09/23.
 */

@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfig {


    /**
     * Configuring WebSecurityConfigurerAdapter is deprecated.
     * <a href="https://spring.io/blog/2022/02/21/spring-security-without-the-websecurityconfigureradapter">check this</a>
     */
//    @Configuration
//    public static class ConfigUsingWebSecurityConfigurer extends WebSecurityConfigurerAdapter {
//
//        @Override
//        public void configure(AuthenticationManagerBuilder auth) throws Exception {
//
//            auth.inMemoryAuthentication()
//                .withUser("piyush").password(passwordEncoder().encode("piyush123")).roles("ADMIN").authorities("READ", "WRITE", "DELETE")
//                .and()
//                .withUser("sandeep").password(passwordEncoder().encode("sandeep123")).roles("USER").authorities("READ", "WRITE");
//        }
//
//        @Override
//        public void configure(HttpSecurity http) throws Exception {
//
//            http.authorizeRequests()
//                .antMatchers("/").permitAll()
//                .antMatchers("/employee/authenticatedUsr/**").authenticated()
//                .antMatchers("/employee/adm/**").hasRole("ADMIN")
//                .antMatchers("/employee/usr/**").hasAnyRole("ADMIN", "USER")
//                .antMatchers("/checkAuthorities/admUser").hasAuthority("DELETE")
//                .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
//                .and()
//                .httpBasic();
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


        @Bean
        public InMemoryUserDetailsManager userDetailsManager(){

            /* With user details object, implementatio of it is User object - with these you can either set authorities or roles. If you set both the one which
            * is set later will override the authorities arraylist with the latest one.
            *
            * */
//            UserDetails user1 = User
//                .withUsername("piyush")
//                .password(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("piyush123"))
//                .roles("ADMIN")
////                .authorities("READ", "WRITE", "DELETE")
//                .build();
//
//            UserDetails user2 = User
//                .withUsername("sandeep")
//                .password(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode("sandeep123"))
//                .roles("USER")
////                .authorities("READ", "WRITE")
//                .build();

            /* Either you can do it below.*/

//            List<SimpleGrantedAuthority> user1SimpleGrantedAuthorities = List.of(
//                new SimpleGrantedAuthority("ROLE_ADMIN"),
//                new SimpleGrantedAuthority("READ"),
//                new SimpleGrantedAuthority("WRITE"),
//                new SimpleGrantedAuthority("DELETE")
//            );
//            UserDetails user1 = User
//                .withUsername("piyush")
//                .password(passwordEncoder().encode("piyush123"))
//                .authorities(user1SimpleGrantedAuthorities)
//                .build();
//
//            List<SimpleGrantedAuthority> user2SimpleGrantedAuthorities = List.of(
//                new SimpleGrantedAuthority("ROLE_USER"),
//                new SimpleGrantedAuthority("READ"),
//                new SimpleGrantedAuthority("WRITE")
//            );
//
//            UserDetails user2 = User
//                .withUsername("sandeep")
//                .password(passwordEncoder().encode("sandeep123"))
//                .authorities(user2SimpleGrantedAuthorities)
//                .build();


            /* OR below but both above and below are eventually setting authorities. */


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
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

            /* You can configure HttpSecurity in following two ways */

            /* Without using lambdas */
//            http.csrf().disable();

            return http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/employee/authenticatedUsr/**").authenticated()
                .antMatchers("/employee/adm/**").hasRole("ADMIN")
                .antMatchers("/employee/usr/**").hasAnyRole("ADMIN", "USER")
                .antMatchers("/checkAuthorities/admUsr").hasAuthority("DELETE")
                .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
                .and()
                .httpBasic()
                .and()
                .build();



            /* With using lamdas */
//            http.csrf(csrf -> csrf.disable());
//            return http.authorizeRequests(auth -> {
//                    auth.antMatchers("/users/authenticatedUsr/**").authenticated()
//                        .antMatchers("/users/adm/**").hasRole("ADMIN")
//                        .antMatchers("/users/usr/**").hasAnyRole("ADMIN", "USER")
//                        .antMatchers("/checkAuthorities/admUsr").hasAuthority("DELETE")
//                        .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
//                        .antMatchers("/users/create/**").permitAll()
//                        .anyRequest().authenticated();
//                })
//                .userDetailsService(userDetailsService)
////                .authenticationProvider() // we could also use this and assign a authentication provider bean as we did above.
//                .httpBasic(Customizer.withDefaults())
//                .build();


        }

        @Bean
        public PasswordEncoder passwordEncoder () {
            return new BCryptPasswordEncoder();
        }

    }

}
