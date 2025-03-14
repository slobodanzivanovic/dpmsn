package com.slobodanzivanovic.dpmsn.core.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.util.Properties;

/**
 * Configuration class for email functionality.
 * <p>
 * This class provides configuration for the JavaMailSender which is used
 * to send emails from the application.
 * </p>
 */
@Configuration
public class EmailConfig {

	@Value("${core.mail.username}")
	private String emailUsername;

	@Value("${core.mail.password}")
	private String emailPassword;

	/**
	 * Configures and provides a JavaMailSender instance.
	 * <p>
	 * Sets up the mail server connection properties including host, port,
	 * authentication, TLS, and timeout settings.
	 * </p>
	 *
	 * @return A configured JavaMailSender instance
	 */
	@Bean
	public JavaMailSender javaMailSender() {
		JavaMailSenderImpl mailSender = new JavaMailSenderImpl();

		mailSender.setHost("mailcluster.loopia.se");
		mailSender.setPort(587);
		mailSender.setUsername(emailUsername);
		mailSender.setPassword(emailPassword);

		Properties props = mailSender.getJavaMailProperties();
		props.put("mail.transport.protocol", "smtp");
		props.put("mail.smtp.auth", "true");
		props.put("mail.smtp.starttls.enable", "true");
		props.put("mail.smtp.connectiontimeout", "5000");
		props.put("mail.debug", "true");

		return mailSender;
	}

}
