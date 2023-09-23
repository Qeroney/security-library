package com.example.demo.security;

import com.example.demo.user.CustomUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Duration;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    public String generateToken(CustomUser userDetails) {
        Map<String, Object> claims = new HashMap<>();

        List<String> roleList = userDetails.getAuthorities().stream()
                                           .map(GrantedAuthority::getAuthority)
                                           .collect(Collectors.toList());
        claims.put("roles", roleList);

        Date issueDate = new Date(System.currentTimeMillis());
        Date expiredDate = new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 2);
        return Jwts.builder().
                   setClaims(claims)
                   .setSubject(userDetails.getUsername())
                   .setId(userDetails.getId().toString())
                   .setIssuedAt(issueDate)
                   .setExpiration(expiredDate)
                   .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                   .compact();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public UUID extractId(String token) {
        return UUID.fromString(extractAllClaims(token).getId());
    }

    public List<String> getRoles(String token) {
        return extractAllClaims(token).get("roles", List.class);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                   .setSigningKey(getSignInKey())
                   .build()
                   .parseClaimsJws(token)
                   .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
