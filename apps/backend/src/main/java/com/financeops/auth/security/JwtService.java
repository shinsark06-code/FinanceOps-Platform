package com.financeops.auth.security;

import com.financeops.auth.exception.JwtException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Slf4j
@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.access-token-expiry}")
    private long accessTokenExpiry;

    @Value("${app.jwt.refresh-token-expiry}")
    private long refreshTokenExpiry;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateAccessToken(Authentication authentication) {
        return generateToken(authentication.getName(), accessTokenExpiry);
    }

    public String generateRefreshToken(String email) {
        return generateToken(email, refreshTokenExpiry);
    }

    private String generateToken(String subject, long expiryTime) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiryTime);

        return Jwts.builder()
                .subject(subject)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    public String getEmailFromToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (ExpiredJwtException e) {
            throw new JwtException("Token has expired", e);
        } catch (UnsupportedJwtException e) {
            throw new JwtException("Unsupported JWT token", e);
        } catch (MalformedJwtException e) {
            throw new JwtException("Invalid JWT token", e);
        } catch (SignatureException e) {
            throw new JwtException("Invalid JWT signature", e);
        } catch (IllegalArgumentException e) {
            throw new JwtException("JWT claims string is empty", e);
        }
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("Expired JWT token");
            return false;
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported JWT token");
            return false;
        } catch (MalformedJwtException e) {
            log.warn("Invalid JWT token");
            return false;
        } catch (SignatureException e) {
            log.warn("Invalid JWT signature");
            return false;
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims string is empty");
            return false;
        }
    }

    public long getAccessTokenExpiry() {
        return accessTokenExpiry;
    }
}
