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

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

	private final AuthenticationService authenticationService;

	@PostMapping("/login")
	public CustomResponse<LoginResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
		LoginResponse response = authenticationService.login(loginRequest);
		return CustomResponse.<LoginResponse>builder()
			.httpStatus(HttpStatus.OK)
			.isSuccess(true)
			.response(response)
			.build();
	}

	@PostMapping("/logout")
	public CustomResponse<Void> logout(HttpServletRequest request) {
		String authHeader = request.getHeader("Authorization");
		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			String token = authHeader.substring(7);
			authenticationService.logout(token);
		}
		return CustomResponse.SUCCESS;
	}

	@PostMapping("/register")
	public CustomResponse<Void> register(@Valid @RequestBody RegisterRequest registerRequest) {
		authenticationService.signup(registerRequest);
		return CustomResponse.<Void>builder()
			.httpStatus(HttpStatus.CREATED)
			.isSuccess(true)
			.build();
	}

	@PostMapping("/verify")
	public CustomResponse<Void> verifyAccount(@Valid @RequestBody VerifyRequest verifyRequest) {
		authenticationService.verifyUser(verifyRequest.email(), verifyRequest.verificationCode());
		return CustomResponse.SUCCESS;
	}

	@PostMapping("/resend-verification")
	public CustomResponse<Void> resendVerification(@RequestParam String email) {
		authenticationService.resendVerificationCode(email);
		return CustomResponse.SUCCESS;
	}

	@PostMapping("/request-password-reset")
	public CustomResponse<Void> requestPasswordReset(@RequestParam String email) {
		authenticationService.requestPasswordReset(email);
		return CustomResponse.SUCCESS;
	}

	@PostMapping("/reset-password")
	public CustomResponse<Void> resetPassword(
		@RequestParam String email,
		@RequestParam String verificationCode,
		@RequestParam String newPassword) {
		authenticationService.resetPassword(email, verificationCode, newPassword);
		return CustomResponse.SUCCESS;
	}

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
