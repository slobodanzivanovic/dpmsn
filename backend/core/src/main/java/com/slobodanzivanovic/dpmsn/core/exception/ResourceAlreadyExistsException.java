package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

public class ResourceAlreadyExistsException extends CoreException {

	private static final String ERROR_CODE = "RESOURCE_ALREADY_EXISTS";

	public ResourceAlreadyExistsException(String message) {
		super(message, HttpStatus.CONFLICT, ERROR_CODE);
	}

	public ResourceAlreadyExistsException(String resourceType, String identifier) {
		super(resourceType + " already exists with identifier: " + identifier, HttpStatus.CONFLICT, ERROR_CODE);
	}

}
