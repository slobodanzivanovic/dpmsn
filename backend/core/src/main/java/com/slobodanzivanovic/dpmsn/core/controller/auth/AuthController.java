package com.slobodanzivanovic.dpmsn.core.controller.auth;

import com.slobodanzivanovic.dpmsn.core.model.auth.dto.request.LoginRequest;
import com.slobodanzivanovic.dpmsn.core.model.auth.dto.request.RegisterRequest;
import com.slobodanzivanovic.dpmsn.core.model.auth.dto.request.VerifyRequest;
import com.slobodanzivanovic.dpmsn.core.model.auth.dto.response.LoginResponse;
import com.slobodanzivanovic.dpmsn.core.model.common.dto.CustomResponse;
import com.slobodanzivanovic.dpmsn.core.service.auth.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for authentication operations.
 * <p>
 * This controller handles authentication-related endpoints including login, logout,
 * registration, account verification, password reset, and OAuth login processing.
 * </p>
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

	private final AuthenticationService authenticationService;

	/**
	 * Process user login.
	 *
	 * @param loginRequest The login credentials containing identifier (username or email) and password
	 * @return Response containing JWT token on successful authentication
	 */
	@PostMapping("/login")
	public CustomResponse<LoginResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
		LoginResponse response = authenticationService.login(loginRequest);
		return CustomResponse.<LoginResponse>builder()
			.httpStatus(HttpStatus.OK)
			.isSuccess(true)
			.response(response)
			.build();
	}

	/**
	 * Process user logout.
	 * <p>
	 * Invalidates the user's JWT token by adding it to the blacklist.
	 * </p>
	 *
	 * @param request The HTTP request containing the JWT token in the Authorization header
	 * @return Success response after logout
	 */
	@PostMapping("/logout")
	public CustomResponse<Void> logout(HttpServletRequest request) {
		String authHeader = request.getHeader("Authorization");
		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			String token = authHeader.substring(7);
			authenticationService.logout(token);
		}
		return CustomResponse.SUCCESS;
	}

	/**
	 * Register a new user.
	 *
	 * @param registerRequest The registration details
	 * @return Success response after registration
	 */
	@PostMapping("/register")
	public CustomResponse<Void> register(@Valid @RequestBody RegisterRequest registerRequest) {
		authenticationService.signup(registerRequest);
		return CustomResponse.<Void>builder()
			.httpStatus(HttpStatus.CREATED)
			.isSuccess(true)
			.build();
	}

	/**
	 * Verify a user account using a verification code.
	 *
	 * @param verifyRequest Request containing email and verification code
	 * @return Success response after verification
	 */
	@PostMapping("/verify")
	public CustomResponse<Void> verifyAccount(@Valid @RequestBody VerifyRequest verifyRequest) {
		authenticationService.verifyUser(verifyRequest.email(), verifyRequest.verificationCode());
		return CustomResponse.SUCCESS;
	}

	/**
	 * Resend verification code to a user's email.
	 *
	 * @param email The email to send the verification code to
	 * @return Success response after sending the verification code
	 */
	@PostMapping("/resend-verification")
	public CustomResponse<Void> resendVerification(@RequestParam String email) {
		authenticationService.resendVerificationCode(email);
		return CustomResponse.SUCCESS;
	}

	/**
	 * Request a password reset for a user.
	 *
	 * @param email The email of the user requesting password reset
	 * @return Success response after sending the password reset code
	 */
	@PostMapping("/request-password-reset")
	public CustomResponse<Void> requestPasswordReset(@RequestParam String email) {
		authenticationService.requestPasswordReset(email);
		return CustomResponse.SUCCESS;
	}

	/**
	 * Reset a user's password using a verification code.
	 *
	 * @param email            The user's email
	 * @param verificationCode The verification code sent to the user's email
	 * @param newPassword      The new password
	 * @return Success response after password reset
	 */
	@PostMapping("/reset-password")
	public CustomResponse<Void> resetPassword(
		@RequestParam String email,
		@RequestParam String verificationCode,
		@RequestParam String newPassword) {
		authenticationService.resetPassword(email, verificationCode, newPassword);
		return CustomResponse.SUCCESS;
	}

	/**
	 * Handle OAuth login redirection.
	 * <p>
	 * This endpoint is called after successful OAuth authentication to generate
	 * a JWT token for the authenticated user.
	 * </p>
	 *
	 * @param authentication The OAuth authentication token from the provider
	 * @return Response containing JWT token for the authenticated user
	 */
	@GetMapping("/oauth-login")
	public ResponseEntity<CustomResponse<LoginResponse>> oauthLogin(OAuth2AuthenticationToken authentication) {
		log.debug("OAuth login endpoint called");

		if (authentication == null) {
			log.error("Authentication object is null");
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
				.body(CustomResponse.<LoginResponse>builder()
					.httpStatus(HttpStatus.UNAUTHORIZED)
					.isSuccess(false)
					.build());
		}

		log.debug("OAuth provider: {}", authentication.getAuthorizedClientRegistrationId());
		log.debug("OAuth attributes: {}", authentication.getPrincipal().getAttributes());

		try {
			String token = authenticationService.handleOAuthLogin(authentication);
			log.debug("JWT token generated successfully");
			LoginResponse response = new LoginResponse(token, 86400000L);

			return ResponseEntity.ok(CustomResponse.<LoginResponse>builder()
				.httpStatus(HttpStatus.OK)
				.isSuccess(true)
				.response(response)
				.build());
		} catch (Exception e) {
			log.error("Error processing OAuth login: {}", e.getMessage(), e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body(CustomResponse.<LoginResponse>builder()
					.httpStatus(HttpStatus.INTERNAL_SERVER_ERROR)
					.isSuccess(false)
					.build());
		}
	}

}
