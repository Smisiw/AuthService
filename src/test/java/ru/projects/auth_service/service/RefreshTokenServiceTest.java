package ru.projects.auth_service.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;
import ru.projects.auth_service.model.RefreshToken;
import ru.projects.auth_service.model.Role;
import ru.projects.auth_service.model.User;
import ru.projects.auth_service.repository.RefreshTokenRepository;
import ru.projects.auth_service.repository.UserRepository;
import ru.projects.auth_service.security.UserDetailsImpl;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private RefreshTokenService refreshTokenService;

    @Test
    void isTokenValid_returnsTrue_whenNotExpired() {
        RefreshToken token = new RefreshToken();
        token.setExpiryDate(Instant.now().plusSeconds(3600));

        assertTrue(refreshTokenService.isTokenValid(token));
        verify(refreshTokenRepository, never()).delete(any());
    }

    @Test
    void isTokenValid_returnsFalse_andDeletes_whenExpired() {
        RefreshToken token = new RefreshToken();
        token.setExpiryDate(Instant.now().minusSeconds(3600));

        assertFalse(refreshTokenService.isTokenValid(token));
        verify(refreshTokenRepository).delete(token);
    }

    @Test
    void createRefreshToken_savesAndReturnsToken() {
        ReflectionTestUtils.setField(refreshTokenService, "refreshTokenExpiration", 86400000L);

        User user = new User();
        user.setEmail("user@test.com");

        UserDetailsImpl userDetails = new UserDetailsImpl(user);
        Authentication authentication = mock(Authentication.class);
        when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userRepository.findByEmail("user@test.com")).thenReturn(Optional.of(user));

        RefreshToken saved = new RefreshToken();
        saved.setToken("generated-token");
        saved.setUser(user);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(saved);

        RefreshToken result = refreshTokenService.createRefreshToken(authentication);

        assertNotNull(result);
        assertEquals(user, result.getUser());
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void updateRefreshToken_deletesOldAndSavesNew() {
        ReflectionTestUtils.setField(refreshTokenService, "refreshTokenExpiration", 86400000L);

        User user = new User();
        user.setEmail("user@test.com");

        RefreshToken oldToken = new RefreshToken();
        oldToken.setToken("old-token");
        oldToken.setUser(user);

        RefreshToken newToken = new RefreshToken();
        newToken.setToken("new-token");
        newToken.setUser(user);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(newToken);

        RefreshToken result = refreshTokenService.updateRefreshToken(oldToken);

        verify(refreshTokenRepository).delete(oldToken);
        verify(refreshTokenRepository).save(any(RefreshToken.class));
        assertEquals("new-token", result.getToken());
    }

    @Test
    void deleteToken_callsRepositoryDelete() {
        RefreshToken token = new RefreshToken();
        token.setToken("some-token");

        refreshTokenService.deleteToken(token);

        verify(refreshTokenRepository).delete(token);
    }

    @Test
    void findByToken_delegatesToRepository() {
        RefreshToken token = new RefreshToken();
        when(refreshTokenRepository.findByToken("abc")).thenReturn(Optional.of(token));

        Optional<RefreshToken> result = refreshTokenService.findByToken("abc");

        assertTrue(result.isPresent());
        assertEquals(token, result.get());
    }
}
