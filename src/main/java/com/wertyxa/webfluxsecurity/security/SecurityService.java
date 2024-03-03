package com.wertyxa.webfluxsecurity.security;

import com.wertyxa.webfluxsecurity.entity.UserEntity;
import com.wertyxa.webfluxsecurity.exception.AuthException;
import com.wertyxa.webfluxsecurity.service.UserService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RequiredArgsConstructor
@Service
public class SecurityService {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.secret}")
    private String secret;
    @Value("${jwt.expiration}")
    private Integer expirationInSeconds;
    @Value("${jwt.issuer}")
    private String issuer;
    private TokenDetails generateToken(UserEntity user){
        var claims = new HashMap<String, Object>() {{
            put("role", user.getRole());
            put("username", user.getUsername());
        }};
        return generateToken(claims, user.getId().toString());
    }
    private TokenDetails generateToken(Map<String, Object> claims, String subject){
        long timeExp = expirationInSeconds * 1000L;
        Date dateExpiration = new Date(new Date().getTime() + timeExp);
        return generateToken(dateExpiration, claims, subject);
    }


    private TokenDetails generateToken(Date expirationDate, Map<String, Object> claims, String subject){
        Date createDate = new Date();
        String token = Jwts.builder()
                .claims(claims)
                .issuer(issuer)
                .subject(subject)
                .issuedAt(createDate)
                .expiration(expirationDate)
                .id(UUID.randomUUID().toString())
                .signWith(Keys.hmacShaKeyFor(secret.getBytes()))
                .compact();
        return TokenDetails.builder()
                .token(token)
                .issueAt(createDate)
                .expiredAt(expirationDate)
                .build();
    }
    public Mono<TokenDetails> authenticate(String username, String password) {
        return userService.getUserByUsername(username)
                .flatMap(user -> {
                    if (!user.getEnabled()) return Mono.error(new AuthException("Account disabled!","USER_ACCOUNT_DISABLED"));
                    if (!passwordEncoder.matches(password, user.getPassword())) return Mono.error(new AuthException("Invalid credentials!","USER_INVALID_CREDENTIALS"));
                    return Mono.just(generateToken(user).toBuilder().userId(user.getId()).build());
                })
                .switchIfEmpty(Mono.error(new AuthException("Invalid credentials!","USER_INVALID_CREDENTIALS")));
    }
}
