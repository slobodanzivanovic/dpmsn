package com.slobodanzivanovic.dpmsn.core.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Base exception class for all application-specific exceptions.
 * <p>
 * This abstract class serves as the foundation for the application's exception hierarchy.
 * It includes common properties such as HTTP status and error code that are used for
 * generating consistent error responses.
 * </p>
 */
@Getter
public abstract class CoreException extends RuntimeException {

	private final HttpStatus httpStatus;
	private final String errorCode;

	/**
	 * Constructs a new CoreException with the specified message, HTTP status, and error code.
	 *
	 * @param message    The detailed error message
	 * @param httpStatus The HTTP status to associate with this exception
	 * @param errorCode  A unique identifier for this type of error
	 */
	protected CoreException(String message, HttpStatus httpStatus, String errorCode) {
		super(message);
		this.httpStatus = httpStatus;
		this.errorCode = errorCode;
	}

	/**
	 * Constructs a new CoreException with the specified message, cause, HTTP status, and error code.
	 *
	 * @param message    The detailed error message
	 * @param cause      The underlying cause of this exception
	 * @param httpStatus The HTTP status to associate with this exception
	 * @param errorCode  A unique identifier for this type of error
	 */
	protected CoreException(String message, Throwable cause, HttpStatus httpStatus, String errorCode) {
		super(message, cause);
		this.httpStatus = httpStatus;
		this.errorCode = errorCode;
	}

}
