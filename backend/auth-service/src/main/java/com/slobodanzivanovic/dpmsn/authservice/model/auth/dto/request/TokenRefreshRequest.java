package com.slobodanzivanovic.dpmsn.authservice.model.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * Represents a request named {@link TokenRefreshRequest} to refresh an access token using a refresh token
 * This record contains the refresh token required for obtaining a new access token
 */
public record TokenRefreshRequest(

	@NotBlank
	String refreshToken

) {
}
