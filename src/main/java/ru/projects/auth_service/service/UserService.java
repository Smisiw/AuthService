package ru.projects.auth_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.projects.auth_service.dto.AuthRequest;
import ru.projects.auth_service.model.User;
import ru.projects.auth_service.repository.RoleRepositiry;
import ru.projects.auth_service.repository.UserRepository;
import ru.projects.auth_service.security.UserDetailsImpl;

import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final RoleRepositiry roleRepositiry;

    public User register(AuthRequest request) throws UsernameNotFoundException {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            log.error("User with username {} already exists", request.getUsername());
            throw new IllegalStateException("Username already exists");
        }
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(request.getPassword());
        user.setRoles(Set.of(roleRepositiry.findByName("ROLE_USER").orElseThrow(
                () -> new IllegalStateException("Role does not exist")
        )));
        return userRepository.save(user);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            log.info("User '{}' loaded successfully", username);
            return new UserDetailsImpl(user);
        } catch (Exception e) {
            log.warn("User '{}' not found", username);
            throw e;
        }

    }
}
