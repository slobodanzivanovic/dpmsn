package com.slobodanzivanovic.dpmsn.core.model.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * DTO for user login requests.
 * <p>
 * This record contains the information required for user authentication.
 * </p>
 *
 * @param identifier Username or email used for authentication
 * @param password   User's password
 */
public record LoginRequest(

	@NotBlank
	String identifier,

	@NotBlank
	String password

) {
}
