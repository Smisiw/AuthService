package ru.projects.auth_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.projects.auth_service.dto.AuthRequest;
import ru.projects.auth_service.dto.RefreshRequest;
import ru.projects.auth_service.exception.TokenException;
import ru.projects.auth_service.model.RefreshToken;
import ru.projects.auth_service.model.User;
import ru.projects.auth_service.repository.RoleRepositiry;
import ru.projects.auth_service.repository.UserRepository;
import ru.projects.auth_service.security.JwtUtil;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final RoleRepositiry roleRepositiry;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public void register(AuthRequest request) throws IllegalStateException {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            log.error("User with username {} already exists", request.getUsername());
            throw new IllegalStateException("Username already exists");
        }
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRoles(Set.of(roleRepositiry.findByName("ROLE_USER").orElseThrow(
                () -> new IllegalStateException("Role does not exist")
        )));
        userRepository.save(user);
        log.info("User '{}' successfully registered at {}", request.getUsername(), LocalDateTime.now());
    }

    public Map<String, String> login(AuthRequest request) throws BadCredentialsException {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );
        String token = jwtUtil.generateToken(authentication);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(authentication);
        log.info("User '{}' successfully logged in at {}", request.getUsername(), LocalDateTime.now());
        return Map.of("token", token, "refresh_token", refreshToken.getToken());
    }

    public Map<String, String> refresh(RefreshRequest request) throws TokenException {
        RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new TokenException("Invalid refresh token"));
        if (!refreshTokenService.isTokenValid(refreshToken)) {
            log.info("Token of user '{}' was expired at {}", refreshToken.getUser().getUsername(), LocalDateTime.now());
            throw new TokenException("Refresh token expired");
        }
        UserDetails userDetails = userService.loadUserByUsername(refreshToken.getUser().getUsername());
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        String newToken = jwtUtil.generateToken(authentication);
        RefreshToken newRefreshToken = refreshTokenService.updateRefreshToken(refreshToken);
        log.info("Token for user '{}' successfully updated at {}", refreshToken.getUser().getUsername(), LocalDateTime.now());
        return Map.of("token", newToken, "refresh_token", newRefreshToken.getToken());
    }

    public void logout(RefreshRequest request) throws TokenException {
        RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new TokenException("Invalid refresh token"));
        refreshTokenService.deleteToken(refreshToken);
        log.info("User '{}' successfully logged out at {}", refreshToken.getUser().getUsername(), LocalDateTime.now());
    }
}
