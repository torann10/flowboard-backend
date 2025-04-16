package szte.flowboard.dto.request;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(String email,
                              @Size(min = 5, max = 20)
                              String username,
                              @Size(min = 8)
                              @Pattern(regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[^\\w\\s]).{8,}$")
                              String password) {}
