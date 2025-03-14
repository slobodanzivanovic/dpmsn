package com.slobodanzivanovic.dpmsn.core.validation.constraint;

import com.slobodanzivanovic.dpmsn.core.validation.validator.NoWhitespaceValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

/**
 * Validation constraint to ensure a string does not contain whitespace.
 * <p>
 * This annotation can be applied to fields or parameters to verify that
 * they do not contain any whitespace characters (spaces, tabs, newlines, etc.).
 * </p>
 */
@Documented
@Constraint(validatedBy = NoWhitespaceValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface NoWhitespace {

	/**
	 * Error message to be used when the validation fails.
	 *
	 * @return The error message
	 */
	String message() default "Field must not contain whitespace";

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

}
