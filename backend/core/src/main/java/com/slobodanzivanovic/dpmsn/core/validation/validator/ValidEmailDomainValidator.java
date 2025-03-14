package com.slobodanzivanovic.dpmsn.core.validation.validator;

import com.slobodanzivanovic.dpmsn.core.validation.constraint.ValidEmailDomain;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Arrays;
import java.util.List;

public class ValidEmailDomainValidator implements ConstraintValidator<ValidEmailDomain, String> {

	private List<String> allowedDomains;
	private List<String> blockedDomains;

	@Override
	public void initialize(ValidEmailDomain constraintAnnotation) {
		this.allowedDomains = Arrays.asList(constraintAnnotation.allowedDomains());
		this.blockedDomains = Arrays.asList(constraintAnnotation.blockedDomains());
	}

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
