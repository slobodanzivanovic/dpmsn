package com.slobodanzivanovic.dpmsn.core.validation.constraint;

import com.slobodanzivanovic.dpmsn.core.validation.validator.PasswordStrengthValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = PasswordStrengthValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface StrongPassword {

	String message() default "Password does not meet strength requirements";

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};

	int minLength() default 8;

	boolean requireUppercase() default true;

	boolean requireLowercase() default true;

	boolean requireDigit() default true;

	boolean requireSpecialChar() default true;

}
