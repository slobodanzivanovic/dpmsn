package com.slobodanzivanovic.dpmsn.core.service.auth;

import com.slobodanzivanovic.dpmsn.core.model.auth.dto.request.LoginRequest;
import com.slobodanzivanovic.dpmsn.core.model.auth.dto.request.RegisterRequest;
import com.slobodanzivanovic.dpmsn.core.model.auth.dto.response.LoginResponse;
import com.slobodanzivanovic.dpmsn.core.model.auth.entity.UserEntity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

/**
 * Service interface for authentication operations.
 */
public interface AuthenticationService {

	/**
	 * Authenticates a user and generates a JWT token.
	 *
	 * @param loginRequest The login request containing credentials
	 * @return A login response containing the JWT token and expiration time
	 */
	LoginResponse login(LoginRequest loginRequest);

	/**
	 * Logs out a user by invalidating their JWT token.
	 *
	 * @param token The JWT token to invalidate
	 */
	void logout(String token);

	/**
	 * Registers a new user in the system.
	 *
	 * @param registerRequest The registration request
	 * @return The created user entity
	 */
	UserEntity signup(RegisterRequest registerRequest);

	/**
	 * Verifies a user account using the verification code.
	 *
	 * @param email            The email of the account to verify
	 * @param verificationCode The verification code sent to the user's email
	 */
	void verifyUser(String email, String verificationCode);

	/**
	 * Resends the verification code to a user's email.
	 *
	 * @param email The email to send the verification code to
	 */
	void resendVerificationCode(String email);

	/**
	 * Initiates a password reset by sending a verification code.
	 *
	 * @param email The email of the account to reset the password for
	 */
	void requestPasswordReset(String email);

	/**
	 * Resets a user's password using the verification code.
	 *
	 * @param email            The email of the account
	 * @param verificationCode The verification code sent to the user's email
	 * @param newPassword      The new password
	 */
	void resetPassword(String email, String verificationCode, String newPassword);

	/**
	 * Handles authentication via OAuth providers.
	 *
	 * @param authentication The OAuth authentication token from the provider
	 * @return The JWT token for the authenticated user
	 */
	String handleOAuthLogin(OAuth2AuthenticationToken authentication);

}
