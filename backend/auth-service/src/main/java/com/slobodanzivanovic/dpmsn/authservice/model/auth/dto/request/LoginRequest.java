package com.slobodanzivanovic.dpmsn.authservice.model.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Represents a login request named {@link LoginRequest} containing the user's email and password
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

	@NotBlank
	private String email;

	@NotBlank
	private String password;

}
