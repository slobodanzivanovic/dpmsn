package com.slobodanzivanovic.dpmsn.apigateway.filter;

import com.slobodanzivanovic.dpmsn.apigateway.client.CoreServiceClient;
import com.slobodanzivanovic.dpmsn.apigateway.model.Token;
import feign.FeignException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.List;

/**
 * Gateway filter that handles JWT authentication for requests
 */
@Component
@Slf4j
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

	public JwtAuthenticationFilter() {
		super(Config.class);
	}

	/**
	 * Configuration class for JwtAuthenticationFilter
	 */
	public static class Config {
		private List<String> publicEndpoints;

		public List<String> getPublicEndpoints() {
			return publicEndpoints;
		}

		public Config setPublicEndpoints(List<String> publicEndpoints) {
			this.publicEndpoints = publicEndpoints;
			return this;
		}
	}

	@Override
	public GatewayFilter apply(Config config) {
		return (exchange, chain) -> {
			String path = exchange.getRequest().getURI().getPath();

			log.debug("Processing request path: {}", path);

			if (config != null && config.getPublicEndpoints() != null) {
				boolean isPublic = false;
				for (String publicEndpoint : config.getPublicEndpoints()) {
					if (publicEndpoint.endsWith("/**")) {
						String prefix = publicEndpoint.substring(0, publicEndpoint.length() - 3);
						if (path.startsWith(prefix)) {
							isPublic = true;
							break;
						}
					} else if (path.equals(publicEndpoint)) {
						isPublic = true;
						break;
					}
				}

				if (isPublic) {
					log.debug("Public endpoint accessed: {}", path);
					return chain.filter(exchange);
				}
			}

			String authorizationHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

			if (Token.isBearerToken(authorizationHeader)) {
				String jwt = Token.getJwt(authorizationHeader);

				ApplicationContext context = exchange.getApplicationContext();
				CoreServiceClient coreServiceClient = context.getBean(CoreServiceClient.class);

				return Mono.fromCallable(() -> {
						coreServiceClient.validateToken(jwt);
						log.debug("Token validation succeeded for path: {}", path);
						return true;
					})
					.subscribeOn(Schedulers.boundedElastic())
					.flatMap(valid -> chain.filter(exchange))
					.onErrorResume(e -> {
						log.error("Token validation failed for path: {}", path, e);
						if (e instanceof FeignException.Unauthorized || e instanceof FeignException.Forbidden) {
							exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
						} else {
							exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
						}
						return exchange.getResponse().setComplete();
					});
			}

			log.warn("Missing or invalid Authorization header for path: {}", path);
			exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
			return exchange.getResponse().setComplete();
		};
	}
}
