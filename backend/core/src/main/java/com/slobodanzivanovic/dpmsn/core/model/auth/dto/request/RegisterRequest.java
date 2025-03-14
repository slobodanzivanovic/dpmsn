package com.slobodanzivanovic.dpmsn.core.model.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * DTO for user registration requests.
 * <p>
 * This record contains the essential information required to register a new user
 * in the system. Additional user details may be added after registration.
 * </p>
 *
 * @param username Desired username for the new user
 * @param email    Email address for the new user
 * @param password Password for the new user account
 */
public record RegisterRequest(

	@NotBlank
	@Size(min = 3, max = 50, message = "Minimum username length is 3 and maximum 50 characters")
	String username,

	@NotBlank
	@Email(message = "Please enter valid e-mail address")
	String email,

	@NotBlank
	@Size(min = 6, max = 40, message = "Minimum password length is 6 and maximum 40 characters")
	String password

) {
}
