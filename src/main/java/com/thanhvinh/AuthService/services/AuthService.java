package com.thanhvinh.AuthService.services;

import com.thanhvinh.AuthService.exceptions.JWTexception;
import com.thanhvinh.AuthService.exceptions.JWTexception;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.websocket.Decoder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

@Slf4j
@Service
public class AuthService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long jwtExpirationInMs;

    @Value("${jwt.prefix}")
    private String prefix;

    public String generateToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationInMs))
                .signWith(SignatureAlgorithm.HS256, secret).compact();
    }

    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
        return claims.getSubject();
    }

    public String getTokenFromRequest(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return getEmailFromToken(authHeader.substring(7));
        } else {
            throw new JWTexception("Invalid JWT token");
        }
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
            return true;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token");
            throw new JWTexception("Invalid JWT token");
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token");
            throw new JWTexception("Expired JWT token");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token");
            throw new JWTexception("Unsupported JWT token");
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty");
            throw new JWTexception("JWT claims string is empty");
        }
    }

}
