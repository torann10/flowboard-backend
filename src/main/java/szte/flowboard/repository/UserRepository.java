package szte.flowboard.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import szte.flowboard.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

}