package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when a user attempts to access a resource they are not authorized for.
 * <p>
 * This exception is thrown when an authenticated user tries to access a resource or
 * perform an operation that requires permissions they do not have. It returns a
 * FORBIDDEN (403) HTTP status.
 * </p>
 */
public class AccessDeniedException extends CoreException {

	private static final String ERROR_CODE = "ACCESS_DENIED";

	/**
	 * Constructs a new AccessDeniedException with the specified message.
	 *
	 * @param message The detailed error message
	 */
	public AccessDeniedException(String message) {
		super(message, HttpStatus.FORBIDDEN, ERROR_CODE);
	}

}
