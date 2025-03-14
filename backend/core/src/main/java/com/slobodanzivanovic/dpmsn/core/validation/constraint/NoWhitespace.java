package com.slobodanzivanovic.dpmsn.core.validation.constraint;

import com.slobodanzivanovic.dpmsn.core.validation.validator.NoWhitespaceValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = NoWhitespaceValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface NoWhitespace {

	String message() default "Field must not contain whitespace";

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};

}
