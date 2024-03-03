package com.wertyxa.webfluxsecurity.rest;

import com.wertyxa.webfluxsecurity.dto.AuthRequestDto;
import com.wertyxa.webfluxsecurity.dto.AuthResponseDto;
import com.wertyxa.webfluxsecurity.dto.UserDto;
import com.wertyxa.webfluxsecurity.entity.UserEntity;
import com.wertyxa.webfluxsecurity.mapper.UserMapper;
import com.wertyxa.webfluxsecurity.repository.UserRepository;
import com.wertyxa.webfluxsecurity.security.CustomPrincipal;
import com.wertyxa.webfluxsecurity.security.SecurityService;
import com.wertyxa.webfluxsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthRestControllerV1 {
    private final SecurityService securityService;
    private final UserService userService;
    private final UserMapper userMapper;

    @PostMapping("/register")
    public Mono<UserDto> register(@RequestBody UserDto dto) {
        UserEntity map = userMapper.map(dto);
        return userService.registerUser(map).map(userMapper::map);
    }

    @PostMapping("/login")
    public Mono<AuthResponseDto> login(@RequestBody AuthRequestDto dto) {
        return securityService.authenticate(dto.getUsername(), dto.getPassword())
                .flatMap(tokenDetails ->
                        Mono.just(AuthResponseDto.builder()
                                        .userId(tokenDetails.getUserId())
                                        .token(tokenDetails.getToken())
                                        .issuedAt(tokenDetails.getIssueAt())
                                        .expiredAt(tokenDetails.getExpiredAt())
                                .build()
                        ));
    }
    @GetMapping("/info")
    public Mono<UserDto> getUserInfo(Authentication authentication){
        CustomPrincipal principal = (CustomPrincipal) authentication.getPrincipal();
        return userService.getUserById(principal.getId())
                .map(userMapper::map);
    }

}
