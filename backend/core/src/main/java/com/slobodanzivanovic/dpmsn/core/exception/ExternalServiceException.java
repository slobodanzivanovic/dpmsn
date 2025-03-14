package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when an external service integration fails.
 * <p>
 * This exception is thrown when communication with an external service (such as email service
 * or OAuth provider) fails. It returns a SERVICE_UNAVAILABLE (503) HTTP status.
 * </p>
 */
public class ExternalServiceException extends CoreException {

	private static final String ERROR_CODE = "EXTERNAL_SERVICE_ERROR";

	/**
	 * Constructs a new ExternalServiceException with the specified message.
	 *
	 * @param message The detailed error message
	 */
	public ExternalServiceException(String message) {
		super(message, HttpStatus.SERVICE_UNAVAILABLE, ERROR_CODE);
	}

	/**
	 * Constructs a new ExternalServiceException with the specified message and cause.
	 *
	 * @param message The detailed error message
	 * @param cause   The underlying cause of this exception
	 */
	public ExternalServiceException(String message, Throwable cause) {
		super(message, cause, HttpStatus.SERVICE_UNAVAILABLE, ERROR_CODE);
	}

}
