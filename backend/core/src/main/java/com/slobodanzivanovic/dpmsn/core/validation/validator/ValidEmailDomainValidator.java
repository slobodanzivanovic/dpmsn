package com.slobodanzivanovic.dpmsn.core.validation.validator;

import com.slobodanzivanovic.dpmsn.core.validation.constraint.ValidEmailDomain;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Arrays;
import java.util.List;

/**
 * Validator for the ValidEmailDomain constraint.
 * <p>
 * This validator implements the logic to check that an email's domain
 * is allowed based on the configured allowlists and blocklists.
 * </p>
 */
public class ValidEmailDomainValidator implements ConstraintValidator<ValidEmailDomain, String> {

	private List<String> allowedDomains;
	private List<String> blockedDomains;

	/**
	 * Initializes the validator with configuration from the annotation.
	 *
	 * @param constraintAnnotation The annotation instance with configuration
	 */
	@Override
	public void initialize(ValidEmailDomain constraintAnnotation) {
		this.allowedDomains = Arrays.asList(constraintAnnotation.allowedDomains());
		this.blockedDomains = Arrays.asList(constraintAnnotation.blockedDomains());
	}

	/**
	 * Validates that the given email's domain is allowed.
	 * <p>
	 * Checks if the domain is in the blocklist (reject) or if it's in
	 * the allowlist when an allowlist is specified.
	 * </p>
	 *
	 * @param email   The email to validate
	 * @param context The constraint validation context
	 * @return true if the email domain is valid, false otherwise
	 */
	@Override
	public boolean isValid(String email, ConstraintValidatorContext context) {
		if (email == null || !email.contains("@")) {
			return true; // let the @Email validator handle this
		}

		String domain = email.substring(email.lastIndexOf('@') + 1).toLowerCase();

		if (!blockedDomains.isEmpty() && blockedDomains.contains(domain)) {
			return false;
		}

		if (allowedDomains.isEmpty()) {
			return true;
		}

		return allowedDomains.contains(domain);
	}
}
