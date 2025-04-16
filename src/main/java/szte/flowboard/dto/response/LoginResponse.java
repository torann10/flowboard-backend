package szte.flowboard.dto.response;

public record LoginResponse(String token, long expiresIn) {
}
