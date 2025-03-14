package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

public class TokenException extends CoreException {

	private static final String ERROR_CODE = "TOKEN_ERROR";

	public TokenException(String message) {
		super(message, HttpStatus.UNAUTHORIZED, ERROR_CODE);
	}

}
