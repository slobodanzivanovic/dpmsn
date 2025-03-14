package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when attempting to create a resource that already exists.
 * <p>
 * This exception is thrown when an operation attempts to create a resource with
 * an identifier that is already in use. It returns a CONFLICT (409) HTTP status.
 * </p>
 */
public class ResourceAlreadyExistsException extends CoreException {

	private static final String ERROR_CODE = "RESOURCE_ALREADY_EXISTS";

	/**
	 * Constructs a new ResourceAlreadyExistsException with the specified message.
	 *
	 * @param message The detailed error message
	 */
	public ResourceAlreadyExistsException(String message) {
		super(message, HttpStatus.CONFLICT, ERROR_CODE);
	}

	/**
	 * Constructs a new ResourceAlreadyExistsException with a formatted message.
	 *
	 * @param resourceType The type of resource that already exists (e.g., "User", "Role")
	 * @param identifier   The identifier that is already in use (e.g., "email: user@mail.com")
	 */
	public ResourceAlreadyExistsException(String resourceType, String identifier) {
		super(resourceType + " already exists with identifier: " + identifier, HttpStatus.CONFLICT, ERROR_CODE);
	}

}
