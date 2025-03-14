package com.slobodanzivanovic.dpmsn.core.model.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * DTO for account verification requests.
 * <p>
 * This record contains the information needed to verify a user account
 * using the verification code sent during registration.
 * </p>
 *
 * @param email            Email address of the account to verify
 * @param verificationCode Verification code sent to the user's email
 */
public record VerifyRequest(

	@NotBlank
	@Email
	String email,

	@NotBlank
	String verificationCode

) {
}
