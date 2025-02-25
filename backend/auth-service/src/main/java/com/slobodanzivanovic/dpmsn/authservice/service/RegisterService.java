package com.slobodanzivanovic.dpmsn.authservice.service;

import com.slobodanzivanovic.dpmsn.authservice.model.auth.User;
import com.slobodanzivanovic.dpmsn.authservice.model.auth.dto.request.RegisterRequest;

/**
 * Service interface named {@link RegisterService} for user registration operations
 * Provides methods for registering a new user
 */
public interface RegisterService {

	/**
	 * Registers a new user with the provided registration details
	 *
	 * @param registerRequest the registration request containing user details (email, password, etc.)
	 * @return the registered {@link User} object
	 */
	User registerUser(final RegisterRequest registerRequest);

}
