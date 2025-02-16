package com.slobodanzivanovic.dpmsn.authservice.model.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * Represents a login request named {@link LoginRequest} containing the user's email and password
 */
public record LoginRequest(

	@NotBlank
	String email,

	@NotBlank
	String password
	
) {
}
