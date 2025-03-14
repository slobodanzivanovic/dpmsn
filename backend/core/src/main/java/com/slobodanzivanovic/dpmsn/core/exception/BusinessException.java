package com.slobodanzivanovic.dpmsn.core.exception;

import org.springframework.http.HttpStatus;

public class BusinessException extends CoreException {

	private static final String ERROR_CODE = "BUSINESS_RULE_VIOLATION";

	public BusinessException(String message) {
		super(message, HttpStatus.BAD_REQUEST, ERROR_CODE);
	}

}
