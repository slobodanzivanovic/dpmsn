package com.slobodanzivanovic.dpmsn.apigateway.config;

import com.slobodanzivanovic.dpmsn.apigateway.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Configuration for API Gateway routes
 */
@Configuration
@RequiredArgsConstructor
public class GatewayConfig {

	private final JwtAuthenticationFilter jwtAuthFilter;

	private static final List<String> PUBLIC_ENDPOINTS = List.of(
		"/api/v1/auth/login",
		"/api/v1/auth/register",
		"/api/v1/auth/verify",
		"/api/v1/auth/resend-verification",
		"/api/v1/auth/request-password-reset",
		"/api/v1/auth/reset-password",
		"/api/v1/auth/oauth-login",
		"/api/v1/auth/oauth2/authorization/**",
		"/login/oauth2/code/**",
		"/api/v1/test/**",
		"/v3/api-docs/**",
		"/swagger-ui/**",
		"/swagger-ui.html",
		"/actuator/**"
	);

	@Bean
	public RouteLocator routes(RouteLocatorBuilder builder) {
		return builder.routes()
			.route("oauth-callback", r -> r.path("/login/oauth2/code/**")
				.filters(f -> f.filter(jwtAuthFilter.apply(new JwtAuthenticationFilter.Config()
					.setPublicEndpoints(List.of("/login/oauth2/code/**")))))
				.uri("lb://core"))

			.route("core-service", r -> r.path("/api/v1/**")
				.filters(f -> f.filter(jwtAuthFilter.apply(new JwtAuthenticationFilter.Config()
					.setPublicEndpoints(PUBLIC_ENDPOINTS))))
				.uri("lb://core"))

//			.route("learning-platform", r -> r.path("/api/learning/**")
//				.filters(f -> f.filter(jwtAuthFilter.apply(new JwtAuthenticationFilter.Config()
//					.setPublicEndpoints(List.of("/api/learning/public/**")))))
//				.uri("lb://learning-platform"))

			.build();
	}
}
