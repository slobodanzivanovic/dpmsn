package com.slobodanzivanovic.dpmsn.userservice.service;

import com.slobodanzivanovic.dpmsn.userservice.model.user.dto.request.TokenInvalidateRequest;

/**
 * Service interface named {@link LogoutService} for handling user logout operations
 */
public interface LogoutService {

	/**
	 * Logs out a user by invalidating the provided token
	 *
	 * @param tokenInvalidateRequest the request containing the token to be invalidated
	 */
	void logout(final TokenInvalidateRequest tokenInvalidateRequest);

}
