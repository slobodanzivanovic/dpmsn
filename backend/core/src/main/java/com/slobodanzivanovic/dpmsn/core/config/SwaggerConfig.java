package com.slobodanzivanovic.dpmsn.core.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

	@Bean
	public OpenAPI customOpenAPI() {
		return new OpenAPI()
			.info(new Info()
				.title("DPMSN API Documentation")
				.description("API documentation for DPMSN")
				.version("v1.0.0")
				.contact(new Contact()
					.name("Slobodan Zivanovic")
					.email("slobodan.zivanovic@programiraj.rs")
					.url("https://github.com/slobodanzivanovic"))
				.license(new License()
					.name("MIT License")
					.url("https://opensource.org/licenses/MIT")));
	}
}
