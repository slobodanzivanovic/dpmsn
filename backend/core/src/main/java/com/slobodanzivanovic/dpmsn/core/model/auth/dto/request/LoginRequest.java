package com.slobodanzivanovic.dpmsn.core.model.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * DTO for user login requests.
 * <p>
 * This record contains the information required for user authentication.
 * </p>
 *
 * @param identifier Username or email used for authentication
 * @param password   User's password
 */
@Schema(description = "Login request data")
public record LoginRequest(

	@Schema(description = "Username or email for login", example = "slobodan or slobodan.zivanovic@programiraj.rs")
	@NotBlank
	String identifier,

	@Schema(description = "User password", example = "Password123!")
	@NotBlank
	String password

) {
}
