package com.wertyxa.webfluxsecurity.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class UnauthorizedException extends ApiException{
    public UnauthorizedException(String message) {
        super(message, "UNAUTHORIZED");
    }
}
