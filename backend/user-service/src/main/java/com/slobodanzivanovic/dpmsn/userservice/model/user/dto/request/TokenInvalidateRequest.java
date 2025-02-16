package com.slobodanzivanovic.dpmsn.userservice.model.user.dto.request;

import jakarta.validation.constraints.NotBlank;

/**
 * Represents a request named {@link TokenInvalidateRequest} to invalidate tokens
 * This record contains the access and refresh tokens that need to be invalidated
 */
public record TokenInvalidateRequest(

	@NotBlank
	String accessToken,

	@NotBlank
	String refreshToken

) {
}
