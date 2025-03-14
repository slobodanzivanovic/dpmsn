package com.slobodanzivanovic.dpmsn.core.model.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
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
@Schema(description = "Account verification request data")
public record VerifyRequest(

	@Schema(description = "Email address of the account to verify", example = "slobodan.zivanovic@programiraj.rs")
	@NotBlank
	@Email
	String email,

	@Schema(description = "Verification code received by email", example = "123456")
	@NotBlank
	String verificationCode

) {
}
