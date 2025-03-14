package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when validation fails for user input.
 * <p>
 * This exception is thrown when input validation fails outside the context of
 * bean validation or request validation. It returns a BAD_REQUEST (400) HTTP status.
 * </p>
 */
public class ValidationException extends CoreException {

	private static final String ERROR_CODE = "VALIDATION_FAILED";

	/**
	 * Constructs a new ValidationException with the specified message.
	 *
	 * @param message The detailed error message describing the validation failure
	 */
	public ValidationException(String message) {
		super(message, HttpStatus.BAD_REQUEST, ERROR_CODE);
	}

}
