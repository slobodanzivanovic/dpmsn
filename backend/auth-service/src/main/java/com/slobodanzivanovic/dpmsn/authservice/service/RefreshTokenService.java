package com.slobodanzivanovic.dpmsn.authservice.service;

import org.springframework.web.bind.annotation.RequestBody;

import com.slobodanzivanovic.dpmsn.authservice.model.auth.dto.request.TokenRefreshRequest;
import com.slobodanzivanovic.dpmsn.authservice.model.auth.dto.response.TokenResponse;
import com.slobodanzivanovic.dpmsn.authservice.model.common.dto.response.CustomResponse;

import jakarta.validation.Valid;

/**
 * Service interface named {@link RefreshTokenService} for handling token refresh operations
 * Provides methods for refreshing access tokens using a refresh token
 */
public interface RefreshTokenService {

	/**
	 * Refreshes the access token using the provided refresh token
	 *
	 * @param tokenRefreshRequest the request containing the refresh token
	 * @return a {@link CustomResponse} containing the {@link TokenResponse} with the new access and refresh tokens
	 */
	CustomResponse<TokenResponse> refreshToken(@RequestBody @Valid final TokenRefreshRequest tokenRefreshRequest);

}
