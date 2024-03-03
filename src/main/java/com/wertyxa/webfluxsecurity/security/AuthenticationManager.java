package com.wertyxa.webfluxsecurity.security;

import com.wertyxa.webfluxsecurity.entity.UserEntity;
import com.wertyxa.webfluxsecurity.exception.UnauthorizedException;
import com.wertyxa.webfluxsecurity.repository.UserRepository;
import com.wertyxa.webfluxsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthenticationManager implements ReactiveAuthenticationManager {
    private final UserService userService;
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        CustomPrincipal principal = (CustomPrincipal) authentication.getPrincipal();
        return userService.getUserById(principal.getId())
                .filter(UserEntity::getEnabled)
                .switchIfEmpty(Mono.error(new UnauthorizedException("User disabled!")))
                .map(userEntity -> authentication);
    }
}
