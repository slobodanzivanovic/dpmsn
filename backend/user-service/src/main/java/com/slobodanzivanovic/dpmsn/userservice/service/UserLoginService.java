package com.slobodanzivanovic.dpmsn.userservice.service;

import com.slobodanzivanovic.dpmsn.userservice.model.user.Token;
import com.slobodanzivanovic.dpmsn.userservice.model.user.dto.request.LoginRequest;

/**
 * Service interface named {@link UserLoginService} for handling user login operations
 */
public interface UserLoginService {

	/**
	 * Logs in a user with the provided login request and returns an access token
	 *
	 * @param loginRequest the request containing login details
	 * @return a {@link Token} instance representing the user's access token
	 */
	Token login(final LoginRequest loginRequest);

}
