package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when authentication fails.
 * <p>
 * This exception is thrown when a user cannot be authenticated due to
 * invalid credentials, account issues, or other authentication problems.
 * It returns an UNAUTHORIZED (401) HTTP status.
 * </p>
 */
public class AuthenticationException extends CoreException {

	private static final String ERROR_CODE = "AUTHENTICATION_FAILED";

	/**
	 * Constructs a new AuthenticationException with the specified message.
	 *
	 * @param message The detailed error message
	 */
	public AuthenticationException(String message) {
		super(message, HttpStatus.UNAUTHORIZED, ERROR_CODE);
	}

}
