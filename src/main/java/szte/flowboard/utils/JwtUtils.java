package szte.flowboard.utils;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import szte.flowboard.model.User;
import szte.flowboard.repository.UserRepository;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtils {
    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private Long jwtExpiration;

    @Value("${jwt.cookie.name}")
    private String cookieName;

    private final UserRepository userRepo;

    public JwtUtils(UserRepository userRepo) {
        this.userRepo = userRepo;
    }

    public Cookie generateJwtCookie(User userPrincipal) {
        int validityInSeconds = (int) ((jwtExpiration / 1000));

        String jwt = Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + (jwtExpiration)))
                .signWith(getSigningKey())
                .compact();

        Cookie cookie = new Cookie(cookieName, jwt);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setSecure(false);
        cookie.setMaxAge(validityInSeconds);

        return cookie;
    }

    public Cookie generateJwtCookie(String token) {
        int validityInSeconds = (int) ((jwtExpiration / 1000));

        Cookie cookie = new Cookie(cookieName, token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setSecure(false);
        cookie.setMaxAge(validityInSeconds);

        return cookie;
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers) {
        final Claims claims = extractAllClaims(token);
        return claimsResolvers.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, Long expiration) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName = extractUsername(token);
        return (userName.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // gets the user's token from cookie
    public String getUserToken(HttpServletRequest request) {
        if(request.getCookies() != null){
            for(Cookie cookie: request.getCookies()){
                if(cookie.getName().equals(cookieName)){
                    return cookie.getValue();
                }
            }
        }
        return "";
    }

    // gets the cookie which contains the user's token
    public Cookie getUserTokenCookie(HttpServletRequest request) {
        if(request.getCookies() != null){
            for(Cookie cookie: request.getCookies()){
                if(cookie.getName().equals(cookieName)){
                    return cookie;
                }
            }
        }
        return null;
    }

    public long getExpirationTime() {
        return jwtExpiration;
    }
}