package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

public class ValidationException extends CoreException {

	private static final String ERROR_CODE = "VALIDATION_FAILED";

	public ValidationException(String message) {
		super(message, HttpStatus.BAD_REQUEST, ERROR_CODE);
	}

}
