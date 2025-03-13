package com.slobodanzivanovic.dpmsn.core.model.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(

	@NotBlank
	String identifier,

	@NotBlank
	String password

) {
}
