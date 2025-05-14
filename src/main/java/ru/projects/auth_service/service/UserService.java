package ru.projects.auth_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.projects.auth_service.model.User;
import ru.projects.auth_service.repository.UserRepository;
import ru.projects.auth_service.security.UserDetailsImpl;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetailsImpl loadUserByUsername(String email) throws UsernameNotFoundException {
        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            log.info("User '{}' loaded successfully", email);
            return new UserDetailsImpl(user);
        } catch (Exception e) {
            log.warn("User '{}' not found", email);
            throw e;
        }

    }
}
