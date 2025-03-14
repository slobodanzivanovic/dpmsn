package com.slobodanzivanovic.dpmsn.core.controller.user;

import com.slobodanzivanovic.dpmsn.core.model.auth.dto.response.UserResponse;
import com.slobodanzivanovic.dpmsn.core.model.auth.entity.UserEntity;
import com.slobodanzivanovic.dpmsn.core.model.auth.mapper.UserMapper;
import com.slobodanzivanovic.dpmsn.core.model.common.dto.CustomResponse;
import com.slobodanzivanovic.dpmsn.core.security.jwt.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Slf4j
public class UserController {

	private final UserMapper userMapper;

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
