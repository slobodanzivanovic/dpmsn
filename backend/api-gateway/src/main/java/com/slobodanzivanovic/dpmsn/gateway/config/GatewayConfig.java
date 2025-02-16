package com.slobodanzivanovic.dpmsn.gateway.config;

import com.slobodanzivanovic.dpmsn.gateway.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Configuration class named {@link GatewayConfig} for setting up API Gateway routes
 */
@Configuration
@RequiredArgsConstructor
public class GatewayConfig {

	private final JwtAuthenticationFilter jwtAuthFilter;

	// Define the list of public endpoints
	private static final List<String> PUBLIC_ENDPOINTS = List.of(
		"/api/authentication/users/register",
		"/api/authentication/users/login",
		"/api/authentication/users/refresh-token",
		"/api/authentication/users/logout"
	);

	/**
	 * Configures the route locator to define the routing rules for the gateway
	 *
	 * @param builder The RouteLocatorBuilder used to build the RouteLocator
	 * @return A RouteLocator with the defined routes
	 */
	@Bean
	public RouteLocator routes(RouteLocatorBuilder builder) {
		return builder.routes()
			.route("auth-service", r -> r.path("/api/authentication/**")
				.filters(f -> f.filter(jwtAuthFilter.apply(new JwtAuthenticationFilter.Config()
					.setPublicEndpoints(PUBLIC_ENDPOINTS))))
				.uri("lb://auth-service"))
			.route("user-service", r -> r.path("/api/users/**")
				.filters(f -> f.filter(jwtAuthFilter.apply(new JwtAuthenticationFilter.Config()
					.setPublicEndpoints(PUBLIC_ENDPOINTS))))
				.uri("lb://user-service"))
			.build();
	}

}
