package com.slobodanzivanovic.dpmsn.core.validation;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Service for handling validation operations.
 * <p>
 * This service provides methods for validating objects against their defined constraints.
 * </p>
 */
@Component
@RequiredArgsConstructor
public class ValidationService {

	private final Validator validator;

	/**
	 * Validates an object against its defined constraints.
	 * <p>
	 * Throws an exception if any violations are found.
	 * </p>
	 *
	 * @param <T>    The type of object to validate
	 * @param object The object to validate
	 * @throws ConstraintViolationException If validation fails
	 */
	public <T> void validate(T object) {
		Set<ConstraintViolation<T>> violations = validator.validate(object);
		if (!violations.isEmpty()) {
			throw new ConstraintViolationException(violations);
		}
	}

	/**
	 * Validates an object and returns the constraint violations.
	 * <p>
	 * Unlike validate(), this method does not throw an exception but returns the violations.
	 * </p>
	 *
	 * @param <T>    The type of object to validate
	 * @param object The object to validate
	 * @return A set of constraint violations, empty if validation passes
	 */
	public <T> Set<ConstraintViolation<T>> validateAndGetViolations(T object) {
		return validator.validate(object);
	}

	/**
	 * Checks if an object is valid according to its defined constraints.
	 *
	 * @param <T>    The type of object to validate
	 * @param object The object to validate
	 * @return true if the object is valid, false otherwise
	 */
	public <T> boolean isValid(T object) {
		return validator.validate(object).isEmpty();
	}

}
