package ru.projects.auth_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.projects.auth_service.model.User;
import ru.projects.auth_service.repository.UserRepository;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;

    public User register(User user) throws UsernameNotFoundException {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            log.error("User with username {} already exists", user.getUsername());
            throw new UsernameNotFoundException("Username already exists");
        }
        return userRepository.save(user);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            log.info("User '{}' loaded successfully", username);
            return new org.springframework.security.core.userdetails.User(
                    user.getUsername(),
                    user.getPassword(),
                    List.of(new SimpleGrantedAuthority(user.getRole()))
            );
        } catch (Exception e) {
            log.warn("User '{}' not found", username);
            throw e;
        }

    }
}
