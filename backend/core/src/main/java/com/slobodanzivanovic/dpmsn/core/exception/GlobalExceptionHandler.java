package com.slobodanzivanovic.dpmsn.core.exception;

import com.slobodanzivanovic.dpmsn.core.model.common.dto.CustomResponse;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

	@ExceptionHandler(CoreException.class)
	public ResponseEntity<CustomResponse<Map<String, Object>>> handleCoreException(
		CoreException ex, HttpServletRequest request) {

		log.error("Core exception occurred: {}", ex.getMessage(), ex);

		Map<String, Object> details = new HashMap<>();
		details.put("message", ex.getMessage());
		details.put("errorCode", ex.getErrorCode());
		details.put("path", request.getRequestURI());
		details.put("timestamp", LocalDateTime.now());

		return ResponseEntity
			.status(ex.getHttpStatus())
			.body(CustomResponse.<Map<String, Object>>builder()
				.httpStatus(ex.getHttpStatus())
				.isSuccess(false)
				.response(details)
				.build());
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<CustomResponse<Map<String, Object>>> handleValidationExceptions(
		MethodArgumentNotValidException ex, HttpServletRequest request) {

		log.error("Validation exception occurred: {}", ex.getMessage());

		String errorMessages = ex.getBindingResult()
			.getFieldErrors()
			.stream()
			.map(DefaultMessageSourceResolvable::getDefaultMessage)
			.collect(Collectors.joining(", "));

		Map<String, Object> validationErrors = new HashMap<>();
		ex.getBindingResult().getFieldErrors().forEach(error ->
			validationErrors.put(error.getField(), error.getDefaultMessage()));

		Map<String, Object> details = new HashMap<>();
		details.put("message", "Validation failed: " + errorMessages);
		details.put("errorCode", "VALIDATION_FAILED");
		details.put("path", request.getRequestURI());
		details.put("timestamp", LocalDateTime.now());
		details.put("errors", validationErrors);

		return ResponseEntity
			.status(HttpStatus.BAD_REQUEST)
			.body(CustomResponse.<Map<String, Object>>builder()
				.httpStatus(HttpStatus.BAD_REQUEST)
				.isSuccess(false)
				.response(details)
				.build());
	}

	@ExceptionHandler(ConstraintViolationException.class)
	public ResponseEntity<CustomResponse<Map<String, Object>>> handleConstraintViolationException(
		ConstraintViolationException ex, HttpServletRequest request) {

		log.error("Constraint violation exception occurred: {}", ex.getMessage());

		Map<String, Object> validationErrors = new HashMap<>();
		ex.getConstraintViolations().forEach(violation ->
			validationErrors.put(violation.getPropertyPath().toString(), violation.getMessage()));

		Map<String, Object> details = new HashMap<>();
		details.put("message", "Constraint violation: " + ex.getMessage());
		details.put("errorCode", "CONSTRAINT_VIOLATION");
		details.put("path", request.getRequestURI());
		details.put("timestamp", LocalDateTime.now());
		details.put("errors", validationErrors);

		return ResponseEntity
			.status(HttpStatus.BAD_REQUEST)
			.body(CustomResponse.<Map<String, Object>>builder()
				.httpStatus(HttpStatus.BAD_REQUEST)
				.isSuccess(false)
				.response(details)
				.build());
	}

	@ExceptionHandler({
		EntityNotFoundException.class,
		UsernameNotFoundException.class
	})
	public ResponseEntity<CustomResponse<Map<String, Object>>> handleNotFoundExceptions(
		Exception ex, HttpServletRequest request) {

		log.error("Not found exception occurred: {}", ex.getMessage());

		Map<String, Object> details = new HashMap<>();
		details.put("message", ex.getMessage());
		details.put("errorCode", "RESOURCE_NOT_FOUND");
		details.put("path", request.getRequestURI());
		details.put("timestamp", LocalDateTime.now());

		return ResponseEntity
			.status(HttpStatus.NOT_FOUND)
			.body(CustomResponse.<Map<String, Object>>builder()
				.httpStatus(HttpStatus.NOT_FOUND)
				.isSuccess(false)
				.response(details)
				.build());
	}

	@ExceptionHandler({
		BadCredentialsException.class,
		DisabledException.class,
		LockedException.class
	})
	public ResponseEntity<CustomResponse<Map<String, Object>>> handleAuthenticationExceptions(
		Exception ex, HttpServletRequest request) {

		log.error("Authentication exception occurred: {}", ex.getMessage());

		HttpStatus status = HttpStatus.UNAUTHORIZED;
		String errorCode = "AUTHENTICATION_FAILED";
		String message = "Authentication failed";

		if (ex instanceof DisabledException) {
			message = "Account is disabled";
			errorCode = "ACCOUNT_DISABLED";
		} else if (ex instanceof LockedException) {
			message = "Account is locked";
			errorCode = "ACCOUNT_LOCKED";
		} else if (ex instanceof BadCredentialsException) {
			message = "Invalid credentials";
		}

		Map<String, Object> details = new HashMap<>();
		details.put("message", message);
		details.put("errorCode", errorCode);
		details.put("path", request.getRequestURI());
		details.put("timestamp", LocalDateTime.now());

		return ResponseEntity
			.status(status)
			.body(CustomResponse.<Map<String, Object>>builder()
				.httpStatus(status)
				.isSuccess(false)
				.response(details)
				.build());
	}

	@ExceptionHandler(MethodArgumentTypeMismatchException.class)
	public ResponseEntity<CustomResponse<Map<String, Object>>> handleTypeMismatchException(
		MethodArgumentTypeMismatchException ex, HttpServletRequest request) {

		log.error("Type mismatch exception occurred: {}", ex.getMessage());

		Map<String, Object> details = new HashMap<>();
		details.put("message", "Type mismatch for parameter: " + ex.getName());
		details.put("errorCode", "TYPE_MISMATCH");
		details.put("path", request.getRequestURI());
		details.put("timestamp", LocalDateTime.now());
		details.put("requiredType", ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "unknown");

		return ResponseEntity
			.status(HttpStatus.BAD_REQUEST)
			.body(CustomResponse.<Map<String, Object>>builder()
				.httpStatus(HttpStatus.BAD_REQUEST)
				.isSuccess(false)
				.response(details)
				.build());
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<CustomResponse<Map<String, Object>>> handleGenericException(
		Exception ex, HttpServletRequest request) {

		log.error("Unexpected exception occurred: {}", ex.getMessage(), ex);

		Map<String, Object> details = new HashMap<>();
		details.put("message", "An unexpected error occurred");
		details.put("errorCode", "INTERNAL_SERVER_ERROR");
		details.put("path", request.getRequestURI());
		details.put("timestamp", LocalDateTime.now());

		return ResponseEntity
			.status(HttpStatus.INTERNAL_SERVER_ERROR)
			.body(CustomResponse.<Map<String, Object>>builder()
				.httpStatus(HttpStatus.INTERNAL_SERVER_ERROR)
				.isSuccess(false)
				.response(details)
				.build());
	}

}
