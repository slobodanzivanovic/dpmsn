package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when there is an issue with a JWT token.
 * <p>
 * This exception is thrown when token validation, parsing, or handling fails.
 * It returns an UNAUTHORIZED (401) HTTP status.
 * </p>
 */
public class TokenException extends CoreException {

	private static final String ERROR_CODE = "TOKEN_ERROR";

	/**
	 * Constructs a new TokenException with the specified message.
	 *
	 * @param message The detailed error message
	 */
	public TokenException(String message) {
		super(message, HttpStatus.UNAUTHORIZED, ERROR_CODE);
	}

}
