package com.devdoc.backend.security;


import com.devdoc.backend.model.UserEntity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class TokenProvider {
    private static final Logger log = LoggerFactory.getLogger(TokenProvider.class);
    private final Key secretKey;

    public TokenProvider() {
        String secret = "your-256-bit-secret"; // 고정된 비밀 키
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String create(UserEntity userEntity) {
        Date expiryDate = Date.from(Instant.now().plus(1L, ChronoUnit.DAYS));
        return Jwts.builder().signWith(this.secretKey).setSubject(userEntity.getId()).setIssuer("demo app").setIssuedAt(new Date()).setExpiration(expiryDate).compact();
    }

    public String validateAndGetUserId(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(this.secretKey).build().parseClaimsJws(token).getBody();
        return claims.getSubject();
    }
}

/*
import com.devdoc.backend.model.UserEntity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Slf4j
@Service
public class TokenProvider {
    private static final String SECRET_KEY = "NMA8JPctFuna59f5";

    public String create(UserEntity userEntity) {
        Date expiryDate = Date.from(
                Instant.now().plus(1, ChronoUnit.DAYS));

        return Jwts.builder()
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .setSubject(userEntity.getId())
                .setIssuer("demo app")
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .compact();
    }

    public String validateAndGetUserId(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }
}*/