package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when processing OAuth authentication fails.
 * <p>
 * This exception is thrown when there's an issue with the OAuth authentication flow,
 * such as missing profile information or failed provider communication.
 * It returns a BAD_REQUEST (400) HTTP status.
 * </p>
 */
public class OAuthProcessingException extends CoreException {

	private static final String ERROR_CODE = "OAUTH_PROCESSING_ERROR";

	/**
	 * Constructs a new OAuthProcessingException with the specified message.
	 *
	 * @param message The detailed error message
	 */
	public OAuthProcessingException(String message) {
		super(message, HttpStatus.BAD_REQUEST, ERROR_CODE);
	}

	/**
	 * Constructs a new OAuthProcessingException with the specified message and cause.
	 *
	 * @param message The detailed error message
	 * @param cause   The underlying cause of this exception
	 */
	public OAuthProcessingException(String message, Throwable cause) {
		super(message, cause, HttpStatus.BAD_REQUEST, ERROR_CODE);
	}

}
