package com.slobodanzivanovic.dpmsn.authservice.model.auth.dto.response;

/**
 * Represents a response named {@link TokenResponse} containing tokens for authentication
 * This record includes the access token, its expiration time, and the refresh token
 */
public record TokenResponse(

	String accessToken,

	Long accessTokenExpiresAt,

	String refreshToken

) {
}
