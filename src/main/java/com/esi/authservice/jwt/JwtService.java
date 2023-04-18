package com.esi.authservice.jwt;

import com.esi.authservice.config.MyUserDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.Resource;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Slf4j
@Component
@AllArgsConstructor
public class JwtService {

    // Secret key for signing the JWT token (replace with your own secret)
    public static final String SECRET = "4D6351665468576D5A7134743777217A25432A462D4A614E645267556B586E32";

    private final MyUserDetailsService userDetailsService;

    // Generate a JWT token for the given username
    public String generateToken(String userName) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userName);
    }

    // Create a JWT token with the given claims and username
    private String createToken(Map<String, Object> claims, String userName) {
        // Load user details by username
        UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

        // Extract user roles, join them with a comma, and store them in rolesClaim
        String rolesClaim = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(", "));
        log.info("claims  {} ", rolesClaim);

        // Add user roles to the claims
        claims.put("roles", rolesClaim);

        // Build the JWT token
        return Jwts.builder()
                .setClaims(claims) // Set custom claims (including roles)
                .setSubject(userName) // Set the subject (username)
                .setIssuedAt(new Date(System.currentTimeMillis())) // Set the issued at date
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // Set the expiration date (1 hour)
                .signWith(signingKey(), SignatureAlgorithm.HS256) // Sign the token with the key and algorithm
                .compact(); // Serialize the token to a compact string
    }

    // Create a signing key from the secret
    private Key signingKey() {
        byte[] keyDecoder = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyDecoder);
    }

    // Extract a specific claim from the token using a custom function
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Extract all claims from the token
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey()) // Set the signing key for verification
                .build()
                .parseClaimsJws(token) // Parse the token and extract the claims
                .getBody(); // Get the claims body
    }

    // Extract the username (subject) from the token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Extract the user roles from the token
    public String extractRoles(String token) {
        return extractAllClaims(token).get("roles", String.class);
    }

    // Extract the expiration date from the token
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Check if the token is expired
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Validate the token by checking if the username matches and if the token is not expired
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        log.info("extractRoles  {} ", extractRoles(token));
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

}
