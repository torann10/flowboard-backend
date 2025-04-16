package szte.flowboard.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import szte.flowboard.dto.request.LoginRequest;
import szte.flowboard.dto.request.RegisterRequest;
import szte.flowboard.dto.response.LoginResponse;
import szte.flowboard.dto.response.MessageResponse;
import szte.flowboard.model.User;
import szte.flowboard.service.UserService;
import szte.flowboard.utils.JwtUtils;

@CrossOrigin
@RestController
@RequestMapping("/users")
public class UserController {
    private final UserService userService;

    private final JwtUtils jwtUtils;

    public UserController(UserService userService, JwtUtils jwtUtils) {
        this.userService = userService;
        this.jwtUtils = jwtUtils;
    }

    @GetMapping
    public String getUsers() {
        return "List of users";
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        try {
            userService.register(request);

            return ResponseEntity.ok(new MessageResponse("Registered successfully"));
        } catch (Exception e) {
            return ResponseEntity
                    .badRequest()
                    .body(e.getMessage());
        }
    }

    @GetMapping("/authenticate")
    public ResponseEntity<?> authenticate() {
        try {
            return ResponseEntity.ok(new MessageResponse("asd"));
        } catch (Exception e) {
            return ResponseEntity
                    .badRequest()
                    .body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request, HttpServletResponse response) {
        try {
            String jwtToken = userService.login(request);
            Cookie jwtCookie = jwtUtils.generateJwtCookie(jwtToken);
            response.addCookie(jwtCookie);
            return ResponseEntity.ok(new MessageResponse("login successful"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }
    }
}
