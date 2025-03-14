package com.slobodanzivanovic.dpmsn.core.controller.user;

import com.slobodanzivanovic.dpmsn.core.model.auth.dto.response.UserResponse;
import com.slobodanzivanovic.dpmsn.core.model.auth.entity.UserEntity;
import com.slobodanzivanovic.dpmsn.core.model.auth.mapper.UserMapper;
import com.slobodanzivanovic.dpmsn.core.model.common.dto.CustomResponse;
import com.slobodanzivanovic.dpmsn.core.security.jwt.CustomUserDetails;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for user operations.
 * NOR FINISHED
 */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Users", description = "User management endpoints")
@SecurityRequirement(name = "bearer-jwt")
public class UserController {

	private final UserMapper userMapper;

	/**
	 * Get the current authenticated user's information.
	 * <p>
	 * Returns information about the currently authenticated user based on
	 * their JWT token.
	 * </p>
	 *
	 * @param userDetails The current user's details from the security context
	 * @return The user information
	 */
	@Operation(
		summary = "Get current user information",
		description = "Returns information about the currently authenticated user"
	)
	@ApiResponses(value = {
		@ApiResponse(
			responseCode = "200",
			description = "Successfully retrieved user information",
			content = @Content(schema = @Schema(implementation = UserResponse.class))
		),
		@ApiResponse(
			responseCode = "401",
			description = "Unauthorized - No valid authentication provided",
			content = @Content
		)
	})
	@GetMapping("/me")
	public CustomResponse<UserResponse> getCurrentUser(@AuthenticationPrincipal CustomUserDetails userDetails) {
		UserEntity user = userDetails.user();
		UserResponse userResponse = userMapper.map(user);

		return CustomResponse.<UserResponse>builder()
			.httpStatus(HttpStatus.OK)
			.isSuccess(true)
			.response(userResponse)
			.build();
	}

}
