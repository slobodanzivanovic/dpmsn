package com.slobodanzivanovic.dpmsn.core.validation.constraint;

import com.slobodanzivanovic.dpmsn.core.validation.validator.PasswordStrengthValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

/**
 * Validation constraint to ensure a password meets strength requirements.
 * <p>
 * This annotation can be applied to password fields to enforce password
 * complexity requirements such as minimum length, character types, etc.
 * </p>
 */
@Documented
@Constraint(validatedBy = PasswordStrengthValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface StrongPassword {

	/**
	 * Error message to be used when the validation fails.
	 *
	 * @return The error message
	 */
	String message() default "Password does not meet strength requirements";

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
	 * Minimum length requirement for the password.
	 *
	 * @return The minimum password length
	 */
	int minLength() default 8;

	/**
	 * Whether uppercase letters are required in the password.
	 *
	 * @return true if uppercase letters are required, false otherwise
	 */
	boolean requireUppercase() default true;

	/**
	 * Whether lowercase letters are required in the password.
	 *
	 * @return true if lowercase letters are required, false otherwise
	 */
	boolean requireLowercase() default true;

	/**
	 * Whether digits are required in the password.
	 *
	 * @return true if digits are required, false otherwise
	 */
	boolean requireDigit() default true;

	/**
	 * Whether special characters are required in the password.
	 *
	 * @return true if special characters are required, false otherwise
	 */
	boolean requireSpecialChar() default true;

}
