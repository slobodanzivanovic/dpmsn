package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

public class ResourceNotFoundException extends CoreException {

	private static final String ERROR_CODE = "RESOURCE_NOT_FOUND";

	public ResourceNotFoundException(String message) {
		super(message, HttpStatus.NOT_FOUND, ERROR_CODE);
	}

	public ResourceNotFoundException(String resourceType, String identifier) {
		super(resourceType + " not found with identifier: " + identifier, HttpStatus.NOT_FOUND, ERROR_CODE);
	}

}
