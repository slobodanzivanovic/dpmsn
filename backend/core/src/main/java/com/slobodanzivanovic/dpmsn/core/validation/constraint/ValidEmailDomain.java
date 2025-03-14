package com.slobodanzivanovic.dpmsn.core.validation.constraint;

import com.slobodanzivanovic.dpmsn.core.validation.validator.ValidEmailDomainValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

/**
 * Validation constraint to ensure an email's domain is allowed or not blocked.
 * <p>
 * This annotation can be applied to email fields to restrict which domains
 * are acceptable based on allowlists or blocklists.
 * </p>
 */
@Documented
@Constraint(validatedBy = ValidEmailDomainValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidEmailDomain {

	/**
	 * Error message to be used when the validation fails.
	 *
	 * @return The error message
	 */
	String message() default "Email domain is not allowed";

	/**
	 * Groups the constraint belongs to.
	 *
	 * @return The groups
	 */
	Class<?>[] groups() default {};

	/**
	 * Payload associated with the constraint.
	 *
	 * @return The payload
	 */
	Class<? extends Payload>[] payload() default {};

	/**
	 * List of allowed email domains.
	 * <p>
	 * If not empty, only emails with these domains will be accepted.
	 * </p>
	 *
	 * @return Array of allowed domains
	 */
	String[] allowedDomains() default {};

	/**
	 * List of blocked email domains.
	 * <p>
	 * Emails with these domains will be rejected.
	 * </p>
	 *
	 * @return Array of blocked domains
	 */
	String[] blockedDomains() default {};

}
