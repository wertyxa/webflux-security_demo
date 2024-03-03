package com.wertyxa.webfluxsecurity.security;

import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

public class UserAuthenticationBearer {
    public static Mono<Authentication> create(JwtHandler.VerificationResult verificationResult){
        var claims = verificationResult.claims;
        var subject = Long.parseLong(claims.getSubject());
        var role = claims.get("role", String.class);
        var username = claims.get("username", String.class);
        var principal = new CustomPrincipal(subject, username);
        var roles = List.of(new SimpleGrantedAuthority(role));
        return Mono.justOrEmpty(new UsernamePasswordAuthenticationToken(principal, null, roles));
    }
}
