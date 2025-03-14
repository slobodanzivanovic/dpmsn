package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

public class ExternalServiceException extends CoreException {

	private static final String ERROR_CODE = "EXTERNAL_SERVICE_ERROR";

	public ExternalServiceException(String message) {
		super(message, HttpStatus.SERVICE_UNAVAILABLE, ERROR_CODE);
	}

	public ExternalServiceException(String message, Throwable cause) {
		super(message, cause, HttpStatus.SERVICE_UNAVAILABLE, ERROR_CODE);
	}

}
