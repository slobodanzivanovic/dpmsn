package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

public class AccessDeniedException extends CoreException {

	private static final String ERROR_CODE = "ACCESS_DENIED";

	public AccessDeniedException(String message) {
		super(message, HttpStatus.FORBIDDEN, ERROR_CODE);
	}

}
