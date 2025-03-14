package com.slobodanzivanovic.dpmsn.core.validation.validator;

import com.slobodanzivanovic.dpmsn.core.validation.constraint.StrongPassword;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class PasswordStrengthValidator implements ConstraintValidator<StrongPassword, String> {

	private int minLength;
	private boolean requireUppercase;
	private boolean requireLowercase;
	private boolean requireDigit;
	private boolean requireSpecialChar;

	@Override
	public void initialize(StrongPassword constraintAnnotation) {
		this.minLength = constraintAnnotation.minLength();
		this.requireUppercase = constraintAnnotation.requireUppercase();
		this.requireLowercase = constraintAnnotation.requireLowercase();
		this.requireDigit = constraintAnnotation.requireDigit();
		this.requireSpecialChar = constraintAnnotation.requireSpecialChar();
	}

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
