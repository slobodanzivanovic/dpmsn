package com.slobodanzivanovic.dpmsn.core.validation;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class ValidationService {

	private final Validator validator;

	public <T> void validate(T object) {
		Set<ConstraintViolation<T>> violations = validator.validate(object);
		if (!violations.isEmpty()) {
			throw new ConstraintViolationException(violations);
		}
	}

	public <T> Set<ConstraintViolation<T>> validateAndGetViolations(T object) {
		return validator.validate(object);
	}

	public <T> boolean isValid(T object) {
		return validator.validate(object).isEmpty();
	}

}
