package szte.flowboard.service;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import szte.flowboard.dto.request.LoginRequest;
import szte.flowboard.dto.request.RegisterRequest;
import szte.flowboard.model.Role;
import szte.flowboard.model.User;
import szte.flowboard.repository.UserRepository;
import szte.flowboard.utils.JwtUtils;

import java.util.*;


@Service
public class UserService {
    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final JwtUtils jwtUtils;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtUtils jwtUtils) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }

    public User register(RegisterRequest request) {
        String hashedPassword = passwordEncoder.encode(request.password());
        User user = new User(
                request.email(),
                request.username(),
                hashedPassword,
                Role.ADMIN
        );
        return this.userRepository.save(user);
    }

    public String login(LoginRequest request) {
        final Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        final String jwtToken = jwtUtils.generateToken((UserDetails) authentication.getPrincipal());

        return jwtToken;
    }

}