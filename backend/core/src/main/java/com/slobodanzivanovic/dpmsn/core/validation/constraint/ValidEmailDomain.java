package com.slobodanzivanovic.dpmsn.core.validation.constraint;

import com.slobodanzivanovic.dpmsn.core.validation.validator.ValidEmailDomainValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = ValidEmailDomainValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidEmailDomain {

	String message() default "Email domain is not allowed";

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};

	String[] allowedDomains() default {};

	String[] blockedDomains() default {};

}
