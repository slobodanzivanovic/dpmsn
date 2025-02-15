package com.slobodanzivanovic.dpmsn.authservice.model.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Represents a request named {@link TokenRefreshRequest} to refresh an access token using a refresh token
 * This class contains the refresh token required for obtaining a new access token
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenRefreshRequest {

	@NotBlank
	private String refreshToken;

}
