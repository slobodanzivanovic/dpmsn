package com.slobodanzivanovic.dpmsn.userservice.service;

import com.slobodanzivanovic.dpmsn.userservice.model.user.Token;
import com.slobodanzivanovic.dpmsn.userservice.model.user.dto.request.TokenRefreshRequest;

/**
 * Service interface named {@link RefreshTokenService} for managing token refresh operations
 */
public interface RefreshTokenService {

	/**
	 * Refreshes a token based on the provided refresh request
	 *
	 * @param tokenRefreshRequest the request containing the refresh details
	 * @return a new {@link Token} instance with refreshed details
	 */
	Token refreshToken(final TokenRefreshRequest tokenRefreshRequest);

}
