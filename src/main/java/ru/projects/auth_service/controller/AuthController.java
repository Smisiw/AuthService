package ru.projects.auth_service.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import ru.projects.auth_service.dto.AuthRequest;
import ru.projects.auth_service.dto.RefreshRequest;
import ru.projects.auth_service.model.RefreshToken;
import ru.projects.auth_service.model.User;
import ru.projects.auth_service.security.JwtUtil;
import ru.projects.auth_service.service.RefreshTokenService;
import ru.projects.auth_service.service.UserService;

import java.time.LocalDateTime;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        try {
            user = userService.register(user);
        } catch (UsernameNotFoundException exception) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", exception.getMessage()));
        }
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
        );

        String token = jwtUtil.generateToken(user.getUsername());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getUsername());

        log.info("User '{}' successfully registered at {}", user.getUsername(), LocalDateTime.now());

        return ResponseEntity.ok(Map.of(
                "token", token,
                "refreshToken", refreshToken.getToken()
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody AuthRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        String token = jwtUtil.generateToken(request.getUsername());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(request.getUsername());

        log.info("User '{}' successfully logged in at {}", request.getUsername(), LocalDateTime.now());

        return ResponseEntity.ok(Map.of(
                "token", token,
                "refreshToken", refreshToken.getToken()
        ));
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refresh(@RequestBody RefreshRequest request) {
        RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid refresh token"));

        if (!refreshTokenService.isTokenValid(refreshToken)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Refresh token expired");
        }

        String newToken = jwtUtil.generateToken(refreshToken.getUser().getUsername());
        return ResponseEntity.ok(Map.of("token", newToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestBody RefreshRequest request) {
        refreshTokenService.findByToken(request.getRefreshToken())
                .ifPresent(refreshToken -> refreshTokenService.deleteByUser(refreshToken.getUser().getUsername()));

        return ResponseEntity.ok("Logged out successfully");
    }
}