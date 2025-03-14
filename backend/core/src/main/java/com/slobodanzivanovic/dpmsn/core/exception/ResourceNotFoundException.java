package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when a requested resource cannot be found.
 * <p>
 * This exception is thrown when an operation is attempted on a resource that does not exist.
 * It returns a NOT_FOUND (404) HTTP status.
 * </p>
 */
public class ResourceNotFoundException extends CoreException {

	private static final String ERROR_CODE = "RESOURCE_NOT_FOUND";

	/**
	 * Constructs a new ResourceNotFoundException with the specified message.
	 *
	 * @param message The detailed error message
	 */
	public ResourceNotFoundException(String message) {
		super(message, HttpStatus.NOT_FOUND, ERROR_CODE);
	}

	/**
	 * Constructs a new ResourceNotFoundException with a formatted message.
	 *
	 * @param resourceType The type of resource that could not be found (e.g., "User", "Role")
	 * @param identifier   The identifier used to look up the resource (e.g., "email: user@mail.com")
	 */
	public ResourceNotFoundException(String resourceType, String identifier) {
		super(resourceType + " not found with identifier: " + identifier, HttpStatus.NOT_FOUND, ERROR_CODE);
	}

}
