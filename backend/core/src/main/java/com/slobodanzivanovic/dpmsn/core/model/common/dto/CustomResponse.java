package com.slobodanzivanovic.dpmsn.core.model.common.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

/**
 * Represents a generic response object named {@link CustomResponse<T>} with standardized fields
 *
 * @param <T> Type of the response payload
 */
@Getter
@Builder
@Schema(description = "Standard API response wrapper")
public class CustomResponse<T> {

	@Builder.Default
	@Schema(description = "Response timestamp", example = "2023-05-15T10:30:45.123")
	private LocalDateTime time = LocalDateTime.now();

	@Schema(description = "HTTP status code", example = "OK")
	private HttpStatus httpStatus;

	@Schema(description = "Success indicator", example = "true")
	private Boolean isSuccess;

	@JsonInclude(JsonInclude.Include.NON_NULL)
	@Schema(description = "Response payload data")
	private T response;

	/**
	 * Default successful response with HTTP OK status and success indicator set to true
	 */
	public static final CustomResponse<Void> SUCCESS = CustomResponse.<Void>builder()
		.httpStatus(HttpStatus.OK)
		.isSuccess(true)
		.build();

	/**
	 * Creates a successful response with the provided payload and HTTP OK status
	 *
	 * @param <T>      Type of the response payload
	 * @param response Response payload
	 * @return CustomResponse instance with success status, HTTP OK, and the
	 * provided payload
	 */
	public static <T> CustomResponse<T> successOf(final T response) {
		return CustomResponse.<T>builder()
			.httpStatus(HttpStatus.OK)
			.isSuccess(true)
			.response(response)
			.build();
	}

}
