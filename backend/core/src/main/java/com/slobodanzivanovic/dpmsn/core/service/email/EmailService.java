package com.slobodanzivanovic.dpmsn.core.service.email;

import jakarta.mail.MessagingException;

import java.util.Map;

/**
 * Service interface for email operations.
 */
public interface EmailService {

	/**
	 * Sends a verification email to a user.
	 *
	 * @param to The recipient email address
	 * @param subject The email subject
	 * @param text The email content (HTML format)
	 * @throws MessagingException If sending the email fails
	 */
	void sendVerificationEmail(String to, String subject, String text) throws MessagingException;

	// TODO: add docstring
	void sendTemplatedEmail(String to, String subject, String templateName, Map<String, Object> templateModel) throws MessagingException;

}
