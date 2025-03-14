package com.slobodanzivanovic.dpmsn.core.controller.email;

import com.slobodanzivanovic.dpmsn.core.model.common.dto.CustomResponse;
import com.slobodanzivanovic.dpmsn.core.service.email.EmailService;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/test")
@RequiredArgsConstructor
@Slf4j
public class EmailTestController {

	private final EmailService emailService;

	@PostMapping("/email")
	public CustomResponse<Void> testEmail(@RequestParam String to) {
		try {
			String subject = "Test Email from DPMSN";
			String htmlMessage = "<html><body>" +
				"<h2>Test Email</h2>" +
				"<p>This is a test email from your DPMSN application.</p>" +
				"<p>If you received this, your email configuration is working correctly.</p>" +
				"</body></html>";

			emailService.sendVerificationEmail(to, subject, htmlMessage);
			log.info("Test email sent to: {}", to);
			return CustomResponse.SUCCESS;
		} catch (MessagingException e) {
			log.error("Failed to send test email: {}", e.getMessage(), e);
			throw new RuntimeException("Failed to send email", e);
		}
	}
	
}
