package com.slobodanzivanovic.dpmsn.core.model.auth.dto.response;

/**
 * DTO for user login responses.
 * <p>
 * This record contains the information returned to the client after
 * successful authentication, including the JWT token and its expiration time.
 * </p>
 *
 * @param token     JWT authentication token
 * @param expiresIn Token expiration time in milliseconds
 */
public record LoginResponse(

	String token,

	long expiresIn

) {
}
