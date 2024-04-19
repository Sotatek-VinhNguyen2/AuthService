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

    private String secret = "8fc3012ccd7213c3b1ace5637a1e9916e644162c006cd1f534dcc5ece87c854d";

    private long jwtExpirationInMs = 86400000;

    private String prefix = "Bearer ";

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
        if (authHeader != null && authHeader.startsWith(prefix)) {
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

    public static void main(String[] args) {
        AuthService authService = new AuthService();
        System.out.println(authService.generateToken("admin@admin.com"));
    }

}
