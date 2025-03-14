package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when a business rule is violated.
 * <p>
 * This exception is thrown when an operation violates a business rule or constraint
 * that is not directly related to validation or authentication. It returns a
 * BAD_REQUEST (400) HTTP status.
 * </p>
 */
public class BusinessException extends CoreException {

	private static final String ERROR_CODE = "BUSINESS_RULE_VIOLATION";

	/**
	 * Constructs a new BusinessException with the specified message.
	 *
	 * @param message The detailed error message describing the business rule violation
	 */
	public BusinessException(String message) {
		super(message, HttpStatus.BAD_REQUEST, ERROR_CODE);
	}

}
