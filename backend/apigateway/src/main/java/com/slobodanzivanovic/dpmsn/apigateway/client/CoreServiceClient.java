package com.slobodanzivanovic.dpmsn.apigateway.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Feign client for interacting with the Core service
 * Used to validate JWT tokens
 */
@FeignClient(name = "core", path = "/api/v1/auth")
public interface CoreServiceClient {
	/**
	 * Validates a JWT token by calling the Core service
	 *
	 * @param token the JWT token to validate
	 */
	@PostMapping("/validate-token")
	void validateToken(@RequestParam String token);
}
