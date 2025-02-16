package com.slobodanzivanovic.dpmsn.authservice.service.impl;

import org.springframework.stereotype.Service;

import com.slobodanzivanovic.dpmsn.authservice.client.UserServiceClient;
import com.slobodanzivanovic.dpmsn.authservice.model.auth.dto.request.TokenInvalidateRequest;
import com.slobodanzivanovic.dpmsn.authservice.model.common.dto.response.CustomResponse;
import com.slobodanzivanovic.dpmsn.authservice.service.LogoutService;

import lombok.RequiredArgsConstructor;

/**
 * Implementation of the {@link LogoutService} interface
 * Handles the logic for user logout by invalidating tokens via the {@link UserServiceClient}
 */
@Service
@RequiredArgsConstructor
public class LogoutServiceImpl implements LogoutService {

	private final UserServiceClient userServiceClient;

	/**
	 * Logs out a user by invalidating the provided tokens
	 *
	 * @param tokenInvalidateRequest the request containing the access and refresh tokens to be invalidated
	 * @return a {@link CustomResponse} indicating the result of the logout operation
	 */
	@Override
	public CustomResponse<Void> logout(TokenInvalidateRequest tokenInvalidateRequest) {
		return userServiceClient.logout(tokenInvalidateRequest);
	}

}
