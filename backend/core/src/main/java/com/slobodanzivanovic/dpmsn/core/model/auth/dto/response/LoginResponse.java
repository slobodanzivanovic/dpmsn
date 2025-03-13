package com.slobodanzivanovic.dpmsn.core.model.auth.dto.response;

public record LoginResponse(

	String token,

	long expiresIn

) {
}
