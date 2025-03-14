package com.slobodanzivanovic.dpmsn.core.model.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

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
@Schema(description = "Login response containing authentication token and expiration time")
public record LoginResponse(

	@Schema(description = "JWT authentication token", example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
	String token,

	@Schema(description = "Token expiration time in milliseconds", example = "86400000")
	long expiresIn

) {
}
