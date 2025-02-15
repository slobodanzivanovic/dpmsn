package com.slobodanzivanovic.dpmsn.authservice.model.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Represents a response named {@link TokenResponse} containing tokens for authentication
 * This class includes the access token, its expiration time, and the refresh token
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenResponse {

	private String accessToken;

	private Long accessTokenExpiresAt;

	private String refreshToken;

}
