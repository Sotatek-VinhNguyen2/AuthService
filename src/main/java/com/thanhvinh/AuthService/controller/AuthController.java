package com.thanhvinh.AuthService.controller;

import com.thanhvinh.AuthService.dtos.JwtResponseDTO;
import com.thanhvinh.AuthService.dtos.JwtVerifyDTO;
import com.thanhvinh.AuthService.dtos.UserDTO;
import com.thanhvinh.AuthService.services.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
@SecurityScheme(type = SecuritySchemeType.HTTP, scheme = "bearer", name = "Authorization")
@Validated
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    public final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @Operation(summary = "Generate JWT Token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Generate JWT Token"),
    })
    @PostMapping("/generate-jwt")
    public ResponseEntity<JwtResponseDTO> generateJwt(@RequestBody UserDTO userDTO) {
        log.info("generateJwt: {}", userDTO.toString());
        String token = authService.generateToken(userDTO.getGmail());
        log.info("Token: {}", token);
        return ResponseEntity.ok().body(new JwtResponseDTO(token));
    }


    @SecurityRequirement(name = AUTHORIZATION)
    @Operation(summary = "Verify JWT Token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Verify JWT Token"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
    })
    @PostMapping("/verify-jwt")
    public ResponseEntity<JwtVerifyDTO> verifyJwt(@RequestHeader("Authorization") String authHeader) {
        log.info("verifyJwt: {}", authHeader);
        String gmail = authService.getTokenFromRequest(authHeader);
        log.info("Gmail: {}", gmail);
        return ResponseEntity.ok().body(new JwtVerifyDTO(gmail));
    }
}
