package com.thanhvinh.AuthService.configs;

import com.thanhvinh.AuthService.exceptions.JWTexception;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(Exception.class)
    @ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorMessage handleAllException(Exception ex, WebRequest request) {
        return new ErrorMessage(500, ex.getLocalizedMessage());
    }

    @ExceptionHandler(JWTexception.class)
    @ResponseStatus(value = HttpStatus.UNAUTHORIZED)
    public ErrorMessage handleUnauthorizedException(Exception ex, WebRequest request) {
        return new ErrorMessage(401, ex.getLocalizedMessage());
    }

}

record ErrorMessage(int code, String message) {
}
