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
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

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
    @Configuration
    public static class ConfigUsingWebSecurityConfigurer extends WebSecurityConfigurerAdapter {

        @Override
        public void configure(AuthenticationManagerBuilder auth) throws Exception {

            /*With in memory user, you can either set roles or authorities but not both at tha same time*/

//            auth.inMemoryAuthentication()
//                .withUser("piyush").password(passwordEncoder().encode("piyush123"))
//                .roles("ADMIN")
////                .authorities("READ", "WRITE", "DELETE")
//                .and()
//                .withUser("sandeep")
//                .password(passwordEncoder().encode("sandeep123"))
//                .roles("USER");
////                .authorities("READ", "WRITE");


            /* If we want to set both we will have to set all authorities and roles within authorities itself */
            auth.inMemoryAuthentication()
                .withUser("piyush").password(passwordEncoder().encode("piyush123"))
                .authorities("ROLE_ADMIN", "READ", "WRITE", "DELETE")
                .and()
                .withUser("sandeep")
                .password(passwordEncoder().encode("sandeep123"))
                .authorities("ROLE_USER", "READ", "WRITE");

        }

        @Override
        public void configure(HttpSecurity http) throws Exception {

            http.csrf().disable();
            http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/employee/authenticatedUsr/**").authenticated()
                .antMatchers("/employee/adm/**").hasRole("ADMIN")
                .antMatchers("/employee/usr/**").hasAnyRole("ADMIN", "USER")
                .antMatchers("/checkAuthorities/admUser").hasAuthority("DELETE")
                .antMatchers("/checkAuthorities/usr").hasAnyAuthority("READ", "WRITE")
                .and()

                /* With formlogin, if you try to access any of the authenticated or authorized resource i.e restricted resource(i.e) backend api.
                *  Spring form login, will redirect you to the login page. */
                .formLogin()
//                .loginPage("/your/custom/page/endpoint") // mostly meant for spring boot MVC app. Default login page is GET "/login". By default this page is permit all.
                .loginProcessingUrl("/mycustomized/endpoint-name") // Enpoint name which is called when we click on submit, it basically overrides the default i.e POST "/login".
                .defaultSuccessUrl("/employee/authenticatedUsr", true) // after login where request should be routed. I have routed to api, it could be html page route.
                .permitAll()
                .and()
                .rememberMe() // default is 2 weeks for remember-me cookie : https://www.baeldung.com/spring-security-remember-me
                .tokenValiditySeconds(60) // we can configure how long remember-me cookie should be valid
                .key("my-secret-to-hash-value-of-cookie")
                .rememberMeCookieName("my-remember-me-cookie")
                .and()
                .logout()// default logout page is GET "/logout"

                /* where to route after successful logout. If here, you provide endpoint to any authorized resource like "/employee/authenticatedUsr".
                 * That will be call but request will be routed to /login page.
                 * As I mentioned above, with formlogin, if you try to access any of the authenticated or authorized resource i.e restricted resource(i.e) backend api.
                 * Spring form login, will redirect you to the login page.
                 */
                .logoutSuccessUrl("/login")
            ;
        }

        @Bean
        public PasswordEncoder passwordEncoder(){
            return new BCryptPasswordEncoder();
        }
    }

}
