package ru.projects.auth_service.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.projects.auth_service.dto.AuthRequest;
import ru.projects.auth_service.dto.RefreshRequest;
import ru.projects.auth_service.exception.TokenException;
import ru.projects.auth_service.model.RefreshToken;
import ru.projects.auth_service.model.Role;
import ru.projects.auth_service.model.User;
import ru.projects.auth_service.repository.RoleRepositiry;
import ru.projects.auth_service.repository.UserRepository;
import ru.projects.auth_service.security.JwtUtil;
import ru.projects.auth_service.security.UserDetailsImpl;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserService userService;
    @Mock
    private JwtUtil jwtUtil;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private UserRepository userRepository;
    @Mock
    private RoleRepositiry roleRepositiry;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthenticationManager authenticationManager;

    @InjectMocks
    private AuthService authService;

    @Test
    void register_success() {
        AuthRequest request = new AuthRequest();
        request.setEmail("user@test.com");
        request.setPassword("password123");

        Role roleUser = new Role();
        roleUser.setName("ROLE_USER");

        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.empty());
        when(roleRepositiry.findByName("ROLE_USER")).thenReturn(Optional.of(roleUser));
        when(passwordEncoder.encode("password123")).thenReturn("encoded");

        authService.register(request);

        verify(userRepository).save(any(User.class));
    }

    @Test
    void register_throwsWhenUserAlreadyExists() {
        AuthRequest request = new AuthRequest();
        request.setEmail("user@test.com");
        request.setPassword("password123");

        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(new User()));

        assertThrows(IllegalStateException.class, () -> authService.register(request));
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_throwsWhenRoleNotFound() {
        AuthRequest request = new AuthRequest();
        request.setEmail("user@test.com");
        request.setPassword("password123");

        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode(any())).thenReturn("encoded");
        when(roleRepositiry.findByName("ROLE_USER")).thenReturn(Optional.empty());

        assertThrows(IllegalStateException.class, () -> authService.register(request));
    }

    @Test
    void login_returnsTokens() {
        AuthRequest request = new AuthRequest();
        request.setEmail("user@test.com");
        request.setPassword("password");

        Authentication authentication = mock(Authentication.class);
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken("refresh-token-value");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(jwtUtil.generateToken(authentication)).thenReturn("access-token");
        when(refreshTokenService.createRefreshToken(authentication)).thenReturn(refreshToken);

        Map<String, String> result = authService.login(request);

        assertEquals("access-token", result.get("token"));
        assertEquals("refresh-token-value", result.get("refresh_token"));
    }

    @Test
    void login_throwsOnBadCredentials() {
        AuthRequest request = new AuthRequest();
        request.setEmail("user@test.com");
        request.setPassword("wrong");

        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        assertThrows(BadCredentialsException.class, () -> authService.login(request));
    }

    @Test
    void refresh_returnsNewTokens_whenTokenValid() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("old-refresh-token");

        User user = new User();
        user.setEmail("user@test.com");
        user.setRoles(Set.of());

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken("old-refresh-token");
        refreshToken.setUser(user);

        RefreshToken newRefreshToken = new RefreshToken();
        newRefreshToken.setToken("new-refresh-token");

        UserDetailsImpl userDetails = new UserDetailsImpl(user);

        when(refreshTokenService.findByToken("old-refresh-token")).thenReturn(Optional.of(refreshToken));
        when(refreshTokenService.isTokenValid(refreshToken)).thenReturn(true);
        when(userService.loadUserByUsername("user@test.com")).thenReturn(userDetails);
        when(jwtUtil.generateToken(any(Authentication.class))).thenReturn("new-access-token");
        when(refreshTokenService.updateRefreshToken(refreshToken)).thenReturn(newRefreshToken);

        Map<String, String> result = authService.refresh(request);

        assertEquals("new-access-token", result.get("token"));
        assertEquals("new-refresh-token", result.get("refresh_token"));
    }

    @Test
    void refresh_throwsWhenTokenNotFound() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("unknown-token");

        when(refreshTokenService.findByToken("unknown-token")).thenReturn(Optional.empty());

        assertThrows(TokenException.class, () -> authService.refresh(request));
    }

    @Test
    void refresh_throwsWhenTokenExpired() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("expired-token");

        User user = new User();
        user.setEmail("user@test.com");

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken("expired-token");
        refreshToken.setUser(user);

        when(refreshTokenService.findByToken("expired-token")).thenReturn(Optional.of(refreshToken));
        when(refreshTokenService.isTokenValid(refreshToken)).thenReturn(false);

        assertThrows(TokenException.class, () -> authService.refresh(request));
    }

    @Test
    void logout_deletesToken() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("some-token");

        User user = new User();
        user.setEmail("user@test.com");

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken("some-token");
        refreshToken.setUser(user);

        when(refreshTokenService.findByToken("some-token")).thenReturn(Optional.of(refreshToken));

        authService.logout(request);

        verify(refreshTokenService).deleteToken(refreshToken);
    }

    @Test
    void logout_throwsWhenTokenNotFound() {
        RefreshRequest request = new RefreshRequest();
        request.setRefreshToken("bad-token");

        when(refreshTokenService.findByToken("bad-token")).thenReturn(Optional.empty());

        assertThrows(TokenException.class, () -> authService.logout(request));
    }
}
