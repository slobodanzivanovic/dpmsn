package com.slobodanzivanovic.dpmsn.core.model.auth.dto.response;

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
public record UserResponse(

	UUID id,

	String username,

	String email,

	String firstName,

	String lastName,

	boolean enabled,

	Set<String> roles

) {
}
