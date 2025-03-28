package ru.projects.auth_service.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.projects.auth_service.dto.AuthRequest;
import ru.projects.auth_service.dto.RefreshRequest;
import ru.projects.auth_service.exception.TokenException;
import ru.projects.auth_service.model.RefreshToken;
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
    public ResponseEntity<Map<String, String>> register(@RequestBody AuthRequest request) {
        request.setPassword(passwordEncoder.encode(request.getPassword()));
        userService.register(request);
        log.info("User '{}' successfully registered at {}", request.getUsername(), LocalDateTime.now());

        return new ResponseEntity<>(HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody AuthRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        String token = jwtUtil.generateToken(authentication);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(authentication);

        log.info("User '{}' successfully logged in at {}", request.getUsername(), LocalDateTime.now());

        return ResponseEntity.ok(Map.of(
                "token", token,
                "refreshToken", refreshToken.getToken()
        ));
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refresh(@RequestBody RefreshRequest request) {
        RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new TokenException("Invalid refresh token"));

        if (!refreshTokenService.isTokenValid(refreshToken)) {
            throw new TokenException("Refresh token expired");
        }

        UserDetails userDetails = userService.loadUserByUsername(refreshToken.getUser().getUsername());
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        String newToken = jwtUtil.generateToken(authentication);
        RefreshToken newRefreshToken = refreshTokenService.updateRefreshToken(refreshToken);
        return ResponseEntity.ok(Map.of(
                "token", newToken,
                "refreshToken", newRefreshToken.getToken()
        ));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestBody RefreshRequest request) {
        RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new TokenException("Invalid refresh token"));
        refreshTokenService.deleteToken(refreshToken);
        log.info("User '{}' successfully logged out at {}", refreshToken.getUser().getUsername(), LocalDateTime.now());
        return ResponseEntity.ok("Logged out successfully");
    }
}