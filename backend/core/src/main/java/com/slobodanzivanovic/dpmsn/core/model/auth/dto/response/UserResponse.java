package com.slobodanzivanovic.dpmsn.core.model.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.Set;
import java.util.UUID;

/**
 * DTO for user information responses.
 * <p>
 * This record contains the user information that is safe to expose to clients,
 * excluding sensitive data like passwords.
 * </p>
 *
 * @param id        Unique identifier of the user
 * @param username  Username of the user
 * @param email     Email address of the user
 * @param firstName First name of the user
 * @param lastName  Last name of the user
 * @param enabled   Flag indicating whether the user account is enabled
 * @param roles     Set of role names assigned to the user
 */
@Schema(description = "User information response")
public record UserResponse(

	@Schema(description = "User's unique identifier", example = "123e4567-e89b-12d3-a456-426614174000")
	UUID id,

	@Schema(description = "Username", example = "slobodan")
	String username,

	@Schema(description = "Email address", example = "slobodan.zivanovic@tuta.com")
	String email,

	@Schema(description = "First name", example = "Slobodan")
	String firstName,

	@Schema(description = "Last name", example = "Zivanovic")
	String lastName,

	@Schema(description = "Whether the account is enabled", example = "true")
	boolean enabled,

	@Schema(description = "User's roles", example = "[\"ROLE_USER\"]")
	Set<String> roles

) {
}
