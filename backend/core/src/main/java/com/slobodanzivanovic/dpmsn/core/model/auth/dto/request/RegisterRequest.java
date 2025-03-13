package com.slobodanzivanovic.dpmsn.core.model.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

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
