package com.example.springbootexamplesjwt.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


/**
 * Referred from : https://github.com/koushikkothagal/spring-security-jwt/blob/master/src/main/java/io/javabrains/springsecurityjwt/util/JwtUtil.java
 *
 * */
@Service
public class JwtUtil {

    private String SECRET_KEY = "piyush-secret";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("name1", "value1");
        claims.put("name2", "value2");
        claims.put("name3", "value3");
        claims.put("name4", "value4");
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {

        /* We can set claims in two ways : either use hashmap and set claims() method and specialized claim method like setSubject(), setIssuedAt(), setExpiration()
        * Or
        * Use setPayload method where we can pass the json string.
        * We can use either one of the method.
        * */

        /* Here setting claims using hashmap and specific claim methods like subject, iat, expiration */
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
            .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();

        /* Here setting claims using payload */
//        try {
//            return Jwts.builder()
//                .setPayload(new ObjectMapper().writeValueAsString(claims))
//                .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
//        } catch (JsonProcessingException e) {
//            throw new RuntimeException(e);
//        }
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}