/*
 *  Copyright (c) 2023 DMG
 *  All Rights Reserved Worldwide.
 *
 *  THIS PROGRAM IS CONFIDENTIAL AND PROPRIETARY TO DMG
 *  AND CONSTITUTES A VALUABLE TRADE SECRET.
 */

package com.example.springbootsecurityform.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
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
//            /*With in memory user, you can either set roles or authorities but not both at tha same time*/
//
////            auth.inMemoryAuthentication()
////                .withUser("piyush").password(passwordEncoder().encode("piyush123"))
////                .roles("ADMIN")
//////                .authorities("READ", "WRITE", "DELETE")
////                .and()
////                .withUser("sandeep")
////                .password(passwordEncoder().encode("sandeep123"))
////                .roles("USER");
//////                .authorities("READ", "WRITE");
//
//
//            /* If we want to set both we will have to set all authorities and roles within authorities itself */
//            auth.inMemoryAuthentication()
//                .withUser("piyush").password(passwordEncoder().encode("piyush123"))
//                .authorities("ROLE_ADMIN", "READ", "WRITE", "DELETE")
//                .and()
//                .withUser("sandeep")
//                .password(passwordEncoder().encode("sandeep123"))
//                .authorities("ROLE_USER", "READ", "WRITE");
//
//        }
//
//        @Override
//        public void configure(HttpSecurity http) throws Exception {
//
//            http.csrf().disable();
//            http.authorizeRequests()
//                .antMatchers("/").permitAll()
//                .antMatchers("/employee/authenticatedUsr/**").authenticated()
//                .antMatchers("/employee/adm/**").hasRole("ADMIN")
//                .antMatchers("/employee/usr/**").hasAnyRole("ADMIN", "USER")
//                .antMatchers("/checkAuthorities/admUser").hasAuthority("DELETE")
//                .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
//                .and()
//
//                /* With formlogin, if you try to access any of the authenticated or authorized resource i.e restricted resource(i.e) backend api.
//                *  Spring form login, will redirect you to the login page. However, if you have successfully logged in and tries to access a resource to which you
//                * to which you dont have permission, then it will give 403 Forbidden error.
//                */
//                .formLogin()
////                .loginPage("/your/custom/page/endpoint") // mostly meant for spring boot MVC app. Default login page is GET "/login". By default this page is permit all.
//                .loginProcessingUrl("/mycustomized/endpoint-name") // Enpoint name which is called when we click on submit, it basically overrides the default i.e POST "/login".
//                .defaultSuccessUrl("/employee/authenticatedUsr", true) // after login where request should be routed. I have routed to api, it could be html page route.
//                .permitAll()
//                .and()
//                .rememberMe() // default is 2 weeks for remember-me cookie : https://www.baeldung.com/spring-security-remember-me
//                .tokenValiditySeconds(60) // we can configure how long remember-me cookie should be valid
//                .key("my-secret-to-hash-value-of-cookie")
//                .rememberMeCookieName("my-remember-me-cookie")
//                .and()
//                .logout()// default logout page is GET "/logout"
//
//                /* where to route after successful logout. If here, you provide endpoint to any authorized resource like "/employee/authenticatedUsr".
//                 * That will be call but request will be routed to /login page.
//                 * As I mentioned above, with formlogin, if you try to access any of the authenticated or authorized resource i.e restricted resource(i.e) backend api.
//                 * Spring form login, will redirect you to the login page.
//                 */
//                .logoutSuccessUrl("/login")
//            ;
//        }
//
//        @Bean
//        public PasswordEncoder passwordEncoder(){
//            return new BCryptPasswordEncoder();
//        }
//    }



    @Configuration
    public static class ConfigUsingSecurityFilterChain {

        @Bean
        public InMemoryUserDetailsManager userDetailsManager() {

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

//            return http
//                .csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/").permitAll()
//                .antMatchers("/employee/authenticatedUsr/**").authenticated()
//                .antMatchers("/employee/adm/**").hasRole("ADMIN")
//                .antMatchers("/employee/usr/**").hasAnyRole("ADMIN", "USER")
//                .antMatchers("/checkAuthorities/admUsr").hasAuthority("DELETE")
//                .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
//                .and()
//                .formLogin()
//                .loginProcessingUrl("/mycustomized/endpoint-name")
//                .defaultSuccessUrl("/employee/authenticatedUsr", true)
//                .permitAll()
//                .and()
//                .rememberMe()
//                .tokenValiditySeconds(60)
//                .key("my-secret-to-hash-value-of-cookie")
//                .rememberMeCookieName("my-remember-me-cookie")
//                .and()
//                .logout()
//                .logoutSuccessUrl("/login")
//                .and()
//                .build();



            /* With using lamdas */
            http.csrf(csrf -> csrf.disable());
            return http.authorizeRequests(auth -> {
                    auth.antMatchers("/employee/authenticatedUsr/**").authenticated()
                        .antMatchers("/employee/adm/**").hasRole("ADMIN")
                        .antMatchers("/employee/usr/**").hasAnyRole("ADMIN", "USER")
                        .antMatchers("/checkAuthorities/admUsr").hasAuthority("DELETE")
                        .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
                        .anyRequest().authenticated();
                })
                .formLogin(formLoginConfigurer -> {
                    formLoginConfigurer.loginProcessingUrl("/mycustomized/endpoint-name")
                        .defaultSuccessUrl("/employee/authenticatedUsr", true)
                        .permitAll();
                })
                .rememberMe(rememberMeConfigurer -> {
                    rememberMeConfigurer.tokenValiditySeconds(60)
                        .key("my-secret-to-hash-value-of-cookie")
                        .rememberMeCookieName("my-remember-me-cookie");
                })
                .logout(logoutConfigurer -> {
                    logoutConfigurer.logoutSuccessUrl("/login");
                })
                .build();
        }

        @Bean
        public PasswordEncoder passwordEncoder(){
            return new BCryptPasswordEncoder();
        }
    }

}
