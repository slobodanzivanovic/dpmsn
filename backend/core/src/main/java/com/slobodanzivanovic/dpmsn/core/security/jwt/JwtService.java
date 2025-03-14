package com.slobodanzivanovic.dpmsn.core.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Service for JWT token operations.
 * <p>
 * This service handles JWT token generation, validation, and parsing operations.
 * It creates tokens with user details, validates them, and extracts information from them.
 * </p>
 */
@Service
@RequiredArgsConstructor
public class JwtService {

	private final TokenBlacklistService tokenBlacklistService;

	@Value("${core.jwt.token.secret-key}")
	private String secretKey;

	@Value("${core.jwt.token.expiration}")
	private Long jwtExpiration;

	/**
	 * Extracts the username from a JWT token.
	 *
	 * @param token The JWT token string
	 * @return The username extracted from the token
	 */
	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	/**
	 * Extracts a specific claim from a JWT token.
	 *
	 * @param <T>            The type of the claim value
	 * @param token          The JWT token string
	 * @param claimsResolver A function to extract the desired claim
	 * @return The extracted claim value
	 */
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}

	/**
	 * Builds a JWT token with the specified claims and expiration.
	 *
	 * @param extraClaims Additional claims to include in the token
	 * @param email       The subject (user email) for the token
	 * @param expiration  The token expiration time in milliseconds
	 * @return The generated JWT token string
	 */
	private String buildToken(Map<String, Object> extraClaims, String email, long expiration) {
		return Jwts
			.builder()
			.claims(extraClaims)
			.subject(email)
			.issuedAt(new Date(System.currentTimeMillis()))
			.expiration(new Date(System.currentTimeMillis() + expiration))
			.signWith(getSignInKey())
			.compact();
	}

	/**
	 * Generates a JWT token for a user.
	 * <p>
	 * Includes user ID, email, and roles as claims in the token.
	 * </p>
	 *
	 * @param userDetails The user details to include in the token
	 * @return The generated JWT token string
	 */
	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();
		claims.put("id", ((CustomUserDetails) userDetails).user().getId());
		claims.put("email", ((CustomUserDetails) userDetails).user().getEmail());
		claims.put("roles", userDetails.getAuthorities()
			.stream()
			.map(GrantedAuthority::getAuthority)
			.collect(Collectors.toList()));

		long expiration = jwtExpiration;

		return buildToken(claims, userDetails.getUsername(), expiration);
	}

	/**
	 * Validates a JWT token.
	 * <p>
	 * Checks if the token is valid by verifying the username matches the provided user details,
	 * the token is not expired, and the token is not blacklisted.
	 * </p>
	 *
	 * @param token       The JWT token to validate
	 * @param userDetails The user details to validate against
	 * @return true if the token is valid, false otherwise
	 */
	public boolean isTokenValid(String token, UserDetails userDetails) {
		final String username = extractUsername(token);
		return username.equals(userDetails.getUsername())
			&& !isTokenExpired(token)
			&& !tokenBlacklistService.isTokenBlacklisted(token);
	}

	/**
	 * Checks if a JWT token is expired.
	 *
	 * @param token The JWT token to check
	 * @return true if the token is expired, false otherwise
	 */
	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	/**
	 * Extracts the expiration date from a JWT token.
	 *
	 * @param token The JWT token
	 * @return The expiration date of the token
	 */
	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	/**
	 * Extracts all claims from a JWT token.
	 *
	 * @param token The JWT token
	 * @return All claims from the token
	 */
	public Claims extractAllClaims(String token) {
		return Jwts
			.parser()
			.verifyWith(getSignInKey())
			.build()
			.parseSignedClaims(token)
			.getPayload();
	}

	/**
	 * Creates a signing key from the base64-encoded secret key.
	 *
	 * @return The SecretKey for JWT signing
	 */
	private SecretKey getSignInKey() {
		byte[] keyBytes = Decoders.BASE64.decode(secretKey);
		return Keys.hmacShaKeyFor(keyBytes);
	}

}
