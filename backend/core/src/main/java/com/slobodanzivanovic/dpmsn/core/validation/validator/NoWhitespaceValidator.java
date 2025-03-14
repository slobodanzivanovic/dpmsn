package com.slobodanzivanovic.dpmsn.core.validation.validator;

import com.slobodanzivanovic.dpmsn.core.validation.constraint.NoWhitespace;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

/**
 * Validator for the NoWhitespace constraint.
 * <p>
 * This validator implements the logic to check that a string value
 * does not contain any whitespace characters (spaces, tabs, newlines).
 * </p>
 */
public class NoWhitespaceValidator implements ConstraintValidator<NoWhitespace, String> {

	/**
	 * Validates that the given string does not contain whitespace.
	 *
	 * @param value   The string to validate
	 * @param context The constraint validation context
	 * @return true if the string is null or does not contain whitespace, false otherwise
	 */
	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {
		if (value == null) {
			return true; // null values are handled by @NotNull annotation
		}

		return !value.contains(" ") && !value.contains("\t") && !value.contains("\n");
	}

}
