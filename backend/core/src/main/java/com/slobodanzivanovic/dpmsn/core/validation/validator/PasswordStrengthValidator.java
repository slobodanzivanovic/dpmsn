package com.slobodanzivanovic.dpmsn.core.validation.validator;

import com.slobodanzivanovic.dpmsn.core.validation.constraint.StrongPassword;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Validator for the StrongPassword constraint.
 * <p>
 * This validator implements the logic to check that a password meets
 * the configured strength requirements such as minimum length, character types, etc.
 * </p>
 */
public class PasswordStrengthValidator implements ConstraintValidator<StrongPassword, String> {

	private int minLength;
	private boolean requireUppercase;
	private boolean requireLowercase;
	private boolean requireDigit;
	private boolean requireSpecialChar;

	/**
	 * Initializes the validator with configuration from the annotation.
	 *
	 * @param constraintAnnotation The annotation instance with configuration
	 */
	@Override
	public void initialize(StrongPassword constraintAnnotation) {
		this.minLength = constraintAnnotation.minLength();
		this.requireUppercase = constraintAnnotation.requireUppercase();
		this.requireLowercase = constraintAnnotation.requireLowercase();
		this.requireDigit = constraintAnnotation.requireDigit();
		this.requireSpecialChar = constraintAnnotation.requireSpecialChar();
	}

	/**
	 * Validates that the given password meets the strength requirements.
	 * <p>
	 * Checks various criteria such as length and character types, and
	 * provides detailed violation messages for each failing criteria.
	 * </p>
	 *
	 * @param password The password to validate
	 * @param context  The constraint validation context
	 * @return true if the password meets all requirements, false otherwise
	 */
	@Override
	public boolean isValid(String password, ConstraintValidatorContext context) {
		if (password == null) {
			return false;
		}

		boolean valid = true;
		List<String> violationMessages = new ArrayList<>();

		if (password.length() < minLength) {
			valid = false;
			violationMessages.add("Password must be at least " + minLength + " characters long");
		}

		if (requireUppercase && !Pattern.compile("[A-Z]").matcher(password).find()) {
			valid = false;
			violationMessages.add("Password must contain at least one uppercase letter");
		}

		if (requireLowercase && !Pattern.compile("[a-z]").matcher(password).find()) {
			valid = false;
			violationMessages.add("Password must contain at least one lowercase letter");
		}

		if (requireDigit && !Pattern.compile("\\d").matcher(password).find()) {
			valid = false;
			violationMessages.add("Password must contain at least one digit");
		}

		if (requireSpecialChar && !Pattern.compile("[^a-zA-Z0-9]").matcher(password).find()) {
			valid = false;
			violationMessages.add("Password must contain at least one special character");
		}

		if (!valid) {
			context.disableDefaultConstraintViolation();

			violationMessages.forEach(message ->
				context.buildConstraintViolationWithTemplate(message)
					.addConstraintViolation()
			);
		}

		return valid;
	}

}
