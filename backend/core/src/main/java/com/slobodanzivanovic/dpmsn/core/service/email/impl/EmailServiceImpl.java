package com.slobodanzivanovic.dpmsn.core.service.email.impl;

import com.slobodanzivanovic.dpmsn.core.service.email.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

/**
 * Implementation of the EmailService interface.
 * <p>
 * This class provides the concrete implementation for sending emails to users
 * using Spring JavaMailSender.
 * </p>
 */
@Service
public class EmailServiceImpl implements EmailService {

	@Autowired
	private JavaMailSender emailSender;

	@Value("${core.mail.username}")
	private String fromEmail;

	/**
	 * Sends a verification email to a user.
	 * <p>
	 * Creates and sends an HTML email to the specified recipient with the given subject and content.
	 * Used for account verification, password reset, and other notification purposes.
	 * </p>
	 *
	 * @param to      The recipient email address
	 * @param subject The email subject
	 * @param text    The email content in HTML format
	 * @throws MessagingException If sending the email fails
	 */
	public void sendVerificationEmail(String to, String subject, String text) throws MessagingException {
		MimeMessage message = emailSender.createMimeMessage();
		MimeMessageHelper helper = new MimeMessageHelper(message, true);

		helper.setFrom(fromEmail);
		helper.setTo(to);
		helper.setSubject(subject);
		helper.setText(text, true);

		emailSender.send(message);
	}

}
