package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

public class AuthenticationException extends CoreException {

	private static final String ERROR_CODE = "AUTHENTICATION_FAILED";

	public AuthenticationException(String message) {
		super(message, HttpStatus.UNAUTHORIZED, ERROR_CODE);
	}

}
