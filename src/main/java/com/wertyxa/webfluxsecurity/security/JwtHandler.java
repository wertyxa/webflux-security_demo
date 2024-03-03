package com.wertyxa.webfluxsecurity.security;

import com.wertyxa.webfluxsecurity.exception.AuthException;
import com.wertyxa.webfluxsecurity.exception.UnauthorizedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.Data;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.Date;

public class JwtHandler {
    private final String secret;

    public JwtHandler(String secret) {
        this.secret = secret;
    }

    public Mono<VerificationResult> check(String accessToken){
        return Mono.just(verify(accessToken))
                .onErrorResume(e->Mono.error(new UnauthorizedException(e.getMessage())));
    }
    private VerificationResult verify(String token){
        Claims claimsFromToken = getClaimsFromToken(token);
        final Date expirationDate = claimsFromToken.getExpiration();
        if (expirationDate.before(new Date())) throw new RuntimeException("Token Expired");
        return new VerificationResult(claimsFromToken, token);
    }
    private Claims getClaimsFromToken(String token){
        return Jwts.parser()
                .setSigningKey(Base64.getEncoder().encodeToString(secret.getBytes()))
                .parseClaimsJws(token)
                .getBody();
    }
    public static class VerificationResult{
        public Claims claims;
        private String token;

        public VerificationResult(Claims claims, String token) {
            this.claims = claims;
            this.token = token;
        }
    }
}
