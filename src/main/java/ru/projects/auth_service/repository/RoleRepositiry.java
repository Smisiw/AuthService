package ru.projects.auth_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.projects.auth_service.model.Role;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RoleRepositiry extends JpaRepository<Role, UUID> {
    Optional<Role> findByName(String name);
}
