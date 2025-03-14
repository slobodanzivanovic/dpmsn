package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

public class OAuthProcessingException extends CoreException {

	private static final String ERROR_CODE = "OAUTH_PROCESSING_ERROR";

	public OAuthProcessingException(String message) {
		super(message, HttpStatus.BAD_REQUEST, ERROR_CODE);
	}

	public OAuthProcessingException(String message, Throwable cause) {
		super(message, cause, HttpStatus.BAD_REQUEST, ERROR_CODE);
	}

}
