package com.slobodanzivanovic.dpmsn.core.service.auth.impl;

import com.slobodanzivanovic.dpmsn.core.exception.*;
import com.slobodanzivanovic.dpmsn.core.model.auth.dto.request.LoginRequest;
import com.slobodanzivanovic.dpmsn.core.model.auth.dto.request.RegisterRequest;
import com.slobodanzivanovic.dpmsn.core.model.auth.dto.response.LoginResponse;
import com.slobodanzivanovic.dpmsn.core.model.auth.entity.RoleEntity;
import com.slobodanzivanovic.dpmsn.core.model.auth.entity.UserEntity;
import com.slobodanzivanovic.dpmsn.core.model.auth.mapper.RequestMapper;
import com.slobodanzivanovic.dpmsn.core.repository.auth.RoleRepository;
import com.slobodanzivanovic.dpmsn.core.repository.auth.UserRepository;
import com.slobodanzivanovic.dpmsn.core.security.jwt.CustomUserDetails;
import com.slobodanzivanovic.dpmsn.core.security.jwt.JwtService;
import com.slobodanzivanovic.dpmsn.core.security.jwt.TokenBlacklistService;
import com.slobodanzivanovic.dpmsn.core.service.auth.AuthenticationService;
import com.slobodanzivanovic.dpmsn.core.service.email.EmailService;
import com.slobodanzivanovic.dpmsn.core.validation.ValidationService;
import jakarta.mail.MessagingException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationAdapter;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Implementation of the AuthenticationService interface.
 * <p>
 * This class provides the core authentication functionality including user login,
 * registration, verification, password management, and OAuth handling.
 * </p>
 */
@Service
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {

	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final BCryptPasswordEncoder passwordEncoder;
	private final EmailService emailService;
	private final TokenBlacklistService tokenBlacklistService;
	private final RequestMapper requestMapper;
	private final ValidationService validationService;

	// login attempt tracking for brute force prevention
	private final Map<String, Integer> loginAttempts = new ConcurrentHashMap<>();
	private final Map<String, LocalDateTime> lockoutTimes = new ConcurrentHashMap<>();
	private static final int MAX_ATTEMPTS = 5;
	private static final int LOCKOUT_MINUTES = 15;
	private static final int MAX_LOCKOUT_MINUTES = 60;

	private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

	public AuthenticationServiceImpl(
		JwtService jwtService,
		AuthenticationManager authenticationManager,
		UserRepository userRepository,
		RoleRepository roleRepository,
		BCryptPasswordEncoder passwordEncoder,
		EmailService emailService,
		TokenBlacklistService tokenBlacklistService,
		RequestMapper requestMapper,
		ValidationService validationService) {

		this.jwtService = jwtService;
		this.authenticationManager = authenticationManager;
		this.userRepository = userRepository;
		this.roleRepository = roleRepository;
		this.passwordEncoder = passwordEncoder;
		this.emailService = emailService;
		this.tokenBlacklistService = tokenBlacklistService;
		this.requestMapper = requestMapper;
		this.validationService = validationService;

		// schedule cleanup of login attempts and lockout times
		scheduler.scheduleAtFixedRate(
			this::cleanupLoginAttempts,
			1,
			1,
			TimeUnit.HOURS
		);
	}

	/**
	 * Authenticates a user and generates a JWT token.
	 * <p>
	 * Validates credentials, handles brute force protection, and generates
	 * a JWT token upon successful authentication.
	 * </p>
	 *
	 * @param loginRequest The login request containing credentials
	 * @return A login response with the JWT token and expiration
	 * @throws ValidationException     If the login request is invalid
	 * @throws AuthenticationException If authentication fails
	 */
	@Override
	@Transactional
	public LoginResponse login(LoginRequest loginRequest) {
		if (loginRequest == null || loginRequest.identifier() == null || loginRequest.password() == null) {
			throw new ValidationException("Identifier and password must not be null");
		}

		checkLockoutStatus(loginRequest.identifier());

		Authentication authentication;
		try {
			authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.identifier(), loginRequest.password())
			);

			loginAttempts.remove(loginRequest.identifier());

		} catch (BadCredentialsException e) {
			recordFailedLoginAttempt(loginRequest.identifier());
			log.warn("Authentication failed for user {}: {}", loginRequest.identifier(), e.getMessage());
			throw new AuthenticationException("Invalid identifier or password");

		} catch (DisabledException e) {
			log.warn("Attempted login to disabled account: {}", loginRequest.identifier());
			throw new AuthenticationException("Account not verified. Please verify your account");

		} catch (Exception e) {
			log.error("Authentication error: {}", e.getMessage(), e);
			throw new AuthenticationException("Authentication failed: " + e.getMessage());
		}

		CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
		if (!userDetails.isEnabled()) {
			throw new AuthenticationException("Account not verified. Please verify your account");
		}

		String token = jwtService.generateToken(userDetails);
		long expirationTime = jwtService.extractClaim(token, claims ->
			claims.getExpiration().getTime() - System.currentTimeMillis());

		log.info("User logged in successfully: {}", userDetails.getUsername());
		return new LoginResponse(token, expirationTime);
	}

	/**
	 * Logs out a user by invalidating their JWT token.
	 *
	 * @param token The JWT token to invalidate
	 * @throws TokenException If the token is invalid
	 */
	@Override
	@Transactional
	public void logout(String token) {
		if (token == null || token.isEmpty()) {
			throw new TokenException("Invalid token");
		}

		tokenBlacklistService.blacklistToken(token);
		SecurityContextHolder.clearContext();
		log.info("User logged out and token blacklisted");
	}

	/**
	 * Registers a new user in the system.
	 * <p>
	 * Creates a new user account, assigns the default role, generates
	 * a verification code, and sends a verification email.
	 * </p>
	 *
	 * @param registerRequest The registration request
	 * @return The created user entity
	 * @throws ValidationException            If validation fails
	 * @throws ResourceAlreadyExistsException If a user with the same username or email exists
	 */
	@Override
	@Transactional
	public UserEntity signup(RegisterRequest registerRequest) {
		validationService.validate(registerRequest);

		if (userRepository.findByEmail(registerRequest.email()).isPresent()) {
			throw new ResourceAlreadyExistsException("User", "email: " + registerRequest.email());
		}

		if (userRepository.findByUsername(registerRequest.username()).isPresent()) {
			throw new ResourceAlreadyExistsException("User", "username: " + registerRequest.username());
		}

		UserEntity newUser = requestMapper.map(registerRequest);

		RoleEntity userRole = roleRepository.findByName("ROLE_USER")
			.orElseThrow(() -> new ResourceNotFoundException("Role", "name: ROLE_USER"));
		newUser.addRole(userRole);

		String verificationCode = generateSecureRandomCode();
		newUser.setVerificationCode(verificationCode);
		newUser.setVerificationCodeExpiresAt(LocalDateTime.now().plusHours(1));

		UserEntity savedUser = userRepository.save(newUser);

		TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronizationAdapter() {
			@Override
			public void afterCommit() {
				try {
					sendVerificationEmail(savedUser);
					log.info("User registered successfully: {}", savedUser.getUsername());
				} catch (Exception e) {
					log.error("Failed to send verification email: {}", e.getMessage(), e);
					// we should consider a retry mechanism here
				}
			}
		});

		return savedUser;
	}

	/**
	 * Verifies a user account using a verification code.
	 * <p>
	 * Checks the provided verification code against the stored code,
	 * validates it hasn't expired, and enables the account if valid.
	 * </p>
	 *
	 * @param email            The email of the account to verify
	 * @param verificationCode The verification code sent to the user's email
	 * @throws ResourceNotFoundException If the user is not found
	 * @throws BusinessException         If the account is already verified or the code has expired
	 * @throws ValidationException       If the verification code is invalid
	 */
	@Override
	@Transactional
	public void verifyUser(String email, String verificationCode) {
		UserEntity user = getUserByEmailOrThrow(email);

		if (user.isEnabled()) {
			throw new BusinessException("Account is already verified");
		}

		if (user.getVerificationCodeExpiresAt() == null ||
			user.getVerificationCodeExpiresAt().isBefore(LocalDateTime.now())) {
			throw new BusinessException("Verification code has expired");
		}

		if (!user.getVerificationCode().equals(verificationCode)) {
			throw new ValidationException("Invalid verification code");
		}

		user.setEnabled(true);
		user.setVerificationCode(null);
		user.setVerificationCodeExpiresAt(null);
		userRepository.save(user);

		log.info("User account verified: {}", email);
	}

	/**
	 * Resends the verification code to a user's email.
	 * <p>
	 * Generates a new verification code, stores it, and sends it
	 * to the user's email for account verification.
	 * </p>
	 *
	 * @param email The email to send the verification code to
	 * @throws ResourceNotFoundException If the user is not found
	 * @throws BusinessException         If the account is already verified
	 */
	@Override
	@Transactional
	public void resendVerificationCode(String email) {
		UserEntity user = getUserByEmailOrThrow(email);

		if (user.isEnabled()) {
			throw new BusinessException("Account is already verified");
		}

		String verificationCode = generateSecureRandomCode();
		user.setVerificationCode(verificationCode);
		user.setVerificationCodeExpiresAt(LocalDateTime.now().plusHours(1));

		userRepository.save(user);

		TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronizationAdapter() {
			@Override
			public void afterCommit() {
				try {
					sendVerificationEmail(user);
					log.info("Verification code resent to: {}", email);
				} catch (Exception e) {
					log.error("Failed to send verification email: {}", e.getMessage(), e);
					// here tho a retry mechanism here
				}
			}
		});
	}

	/**
	 * Initiates a password reset by sending a verification code.
	 * <p>
	 * Generates a verification code, stores it with a short expiration time,
	 * and sends it to the user's email for password reset.
	 * </p>
	 *
	 * @param email The email of the account to reset the password for
	 * @throws ResourceNotFoundException If the user is not found
	 */
	@Override
	@Transactional
	public void requestPasswordReset(String email) {
		UserEntity user = getUserByEmailOrThrow(email);

		String verificationCode = generateSecureRandomCode();
		user.setVerificationCode(verificationCode);
		user.setVerificationCodeExpiresAt(LocalDateTime.now().plusMinutes(15));

		userRepository.save(user);

		TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronizationAdapter() {
			@Override
			public void afterCommit() {
				try {
					sendPasswordResetEmail(user);
					log.info("Password reset requested for: {}", email);
				} catch (Exception e) {
					log.error("Failed to send password reset email: {}", e.getMessage(), e);
					// here tho retry mechanism
				}
			}
		});
	}

	/**
	 * Resets a user's password using the verification code.
	 * <p>
	 * Validates the verification code, checks it hasn't expired,
	 * and updates the user's password if all checks pass.
	 * </p>
	 *
	 * @param email            The email of the account
	 * @param verificationCode The verification code sent to the user's email
	 * @param newPassword      The new password
	 * @throws ResourceNotFoundException If the user is not found
	 * @throws BusinessException         If the verification code has expired
	 * @throws ValidationException       If the verification code is invalid or the password is too weak
	 */
	@Override
	@Transactional
	public void resetPassword(String email, String verificationCode, String newPassword) {
		UserEntity user = getUserByEmailOrThrow(email);

		if (user.getVerificationCodeExpiresAt() == null ||
			user.getVerificationCodeExpiresAt().isBefore(LocalDateTime.now())) {
			throw new BusinessException("Verification code has expired");
		}

		if (!user.getVerificationCode().equals(verificationCode)) {
			throw new ValidationException("Invalid verification code");
		}

		if (newPassword.length() < 8) {
			throw new ValidationException("Password must be at least 8 characters long");
		}

		user.setPassword(passwordEncoder.encode(newPassword));
		user.setVerificationCode(null);
		user.setVerificationCodeExpiresAt(null);
		userRepository.save(user);

		log.info("Password reset successful for: {}", email);
	}

	/**
	 * Handles authentication via OAuth providers.
	 * <p>
	 * Extracts user information from the OAuth authentication token,
	 * creates or retrieves the user account, and generates a JWT token.
	 * </p>
	 *
	 * @param authentication The OAuth authentication token from the provider
	 * @return The JWT token for the authenticated user
	 * @throws OAuthProcessingException If OAuth processing fails
	 */
	@Override
	@Transactional
	public String handleOAuthLogin(OAuth2AuthenticationToken authentication) {
		if (authentication == null || authentication.getPrincipal() == null) {
			log.error("Authentication token or principal is null");
			throw new OAuthProcessingException("Authentication token or principal is null");
		}

		try {
			OAuth2User oAuth2User = authentication.getPrincipal();
			String provider = authentication.getAuthorizedClientRegistrationId();

			log.debug("OAuth2 login attempt with provider: {}", provider);

			String email = extractEmailFromOAuth(oAuth2User, provider);
			log.debug("Extracted email: {}", email);

			if (email == null) {
				log.error("Email not provided by OAuth provider {}", provider);
				throw new OAuthProcessingException("Email not provided by OAuth provider");
			}

			String name = extractNameFromOAuth(oAuth2User, provider);
			log.debug("Extracted name: {}", name);

			UserEntity user = userRepository.findByEmail(email)
				.orElseGet(() -> {
					log.debug("User not found by email, creating new user");
					UserEntity newUser = createOAuthUser(name, email, provider);
					log.debug("New user created with ID: {}", newUser.getId());
					return newUser;
				});

			log.debug("User found/created: {}", user.getId());

			CustomUserDetails userDetails = new CustomUserDetails(user);
			String token = jwtService.generateToken(userDetails);
			log.debug("JWT token generated successfully");

			return token;
		} catch (OAuthProcessingException e) {
			throw e;
		} catch (Exception e) {
			log.error("Unexpected error during OAuth processing: {}", e.getMessage(), e);
			throw new OAuthProcessingException("Failed to process OAuth authentication", e);
		}
	}

	/**
	 * Scheduled task to clean up expired verification codes.
	 * <p>
	 * Runs periodically to find and clear expired verification codes
	 * from user accounts that have not been verified.
	 * </p>
	 */
	@Scheduled(cron = "0 0 * * * ?")
	@Transactional
	public void cleanupExpiredVerificationCodes() {
		log.info("Cleaning up expired verification codes");
		LocalDateTime now = LocalDateTime.now();

		List<UserEntity> usersWithExpiredCodes = userRepository.findByVerificationCodeExpiresAtBeforeAndEnabledFalse(now);

		for (UserEntity user : usersWithExpiredCodes) {
			log.debug("Clearing expired verification code for user: {}", user.getEmail());
			user.setVerificationCode(null);
			user.setVerificationCodeExpiresAt(null);
		}

		if (!usersWithExpiredCodes.isEmpty()) {
			userRepository.saveAll(usersWithExpiredCodes);
			log.info("Cleaned up {} expired verification codes", usersWithExpiredCodes.size());
		}
	}

	/**
	 * Retrieves a user by email or throws an exception if not found.
	 *
	 * @param email The email to look up
	 * @return The user entity
	 * @throws ResourceNotFoundException If no user is found with the given email
	 */
	private UserEntity getUserByEmailOrThrow(String email) {
		return userRepository.findByEmail(email)
			.orElseThrow(() -> new ResourceNotFoundException("User", "email: " + email));
	}

	/**
	 * Generates a secure random verification code.
	 * <p>
	 * Creates a 6-digit numeric code for account verification or password reset.
	 * </p>
	 *
	 * @return A random 6-digit code as a string
	 */
	private String generateSecureRandomCode() {
		SecureRandom random = new SecureRandom();
		int code = 100000 + random.nextInt(900000);
		return String.valueOf(code);
	}

	/**
	 * Sends an account verification email to a user.
	 * <p>
	 * Creates and sends an HTML email containing the verification code
	 * and instructions for account verification.
	 * </p>
	 *
	 * @param user The user to send the verification email to
	 * @throws ExternalServiceException If sending the email fails
	 */
	private void sendVerificationEmail(UserEntity user) {
		String subject = "Please verify your DPMSN account";
		String htmlMessage = "<html><body>" +
			"<h2>Welcome to DPMSN</h2>" +
			"<p>Please use the following code to verify your email: <strong>" +
			user.getVerificationCode() + "</strong></p>" +
			"<p>This code will expire in 1 hour.</p>" +
			"</body></html>";

		try {
			emailService.sendVerificationEmail(user.getEmail(), subject, htmlMessage);
		} catch (MessagingException e) {
			log.error("Failed to send verification email: {}", e.getMessage(), e);
			throw new ExternalServiceException("Error sending verification email", e);
		}
	}

	/**
	 * Sends a password reset email to a user.
	 * <p>
	 * Creates and sends an HTML email containing the verification code
	 * and instructions for password reset.
	 * </p>
	 *
	 * @param user The user to send the password reset email to
	 * @throws ExternalServiceException If sending the email fails
	 */
	private void sendPasswordResetEmail(UserEntity user) {
		String subject = "DPMSN Password Reset";
		String htmlMessage = "<html><body>" +
			"<h2>Password Reset Request</h2>" +
			"<p>Please use the following code to reset your password: <strong>" +
			user.getVerificationCode() + "</strong></p>" +
			"<p>This code will expire in 15 minutes.</p>" +
			"<p>If you did not request this reset, please ignore this email.</p>" +
			"</body></html>";

		try {
			emailService.sendVerificationEmail(user.getEmail(), subject, htmlMessage);
		} catch (MessagingException e) {
			log.error("Failed to send password reset email: {}", e.getMessage(), e);
			throw new ExternalServiceException("Error sending password reset email", e);
		}
	}

	/**
	 * Extracts the email address from OAuth2 user data.
	 * <p>
	 * Attempts to get the email from the provider-specific attributes.
	 * </p>
	 *
	 * @param oAuth2User The OAuth2 user data
	 * @param provider   The OAuth provider name
	 * @return The extracted email or null if not available
	 */
	private String extractEmailFromOAuth(OAuth2User oAuth2User, String provider) {
		String email = null;

		if ("google".equals(provider)) {
			email = oAuth2User.getAttribute("email");
		} else if ("github".equals(provider)) {
			email = oAuth2User.getAttribute("email");

			// TODO: GitHub may not return email directly
			if (email == null) {
				log.warn("GitHub did not provide email directly.. TODO: implementing GitHub API call to fetch private emails");
			}
		}

		return email;
	}

	/**
	 * Extracts the name from OAuth2 user data.
	 * <p>
	 * Attempts to get the name or username from the provider-specific attributes.
	 * </p>
	 *
	 * @param oAuth2User The OAuth2 user data
	 * @param provider   The OAuth provider name
	 * @return The extracted name
	 * @throws OAuthProcessingException If the provider is not supported
	 */
	private String extractNameFromOAuth(OAuth2User oAuth2User, String provider) {
		if ("google".equals(provider)) {
			return oAuth2User.getAttribute("name");
		} else if ("github".equals(provider)) {
			return oAuth2User.getAttribute("login");
		} else {
			throw new OAuthProcessingException("Unsupported provider: " + provider);
		}
	}

	/**
	 * Creates a new user from OAuth authentication data.
	 * <p>
	 * Generates a username and random password, assigns the default role,
	 * and enables the account without requiring email verification.
	 * </p>
	 *
	 * @param name     The user's name from OAuth
	 * @param email    The user's email from OAuth
	 * @param provider The OAuth provider name
	 * @return The created user entity
	 * @throws OAuthProcessingException If user creation fails
	 */
	private UserEntity createOAuthUser(String name, String email, String provider) {
		try {
			log.debug("Creating OAuth user with name: {} and email: {}", name, email);

			UserEntity newUser = UserEntity.builder()
				.email(email)
				.username(generateUniqueUsername(name))
				.firstName(name != null ? name : "User")
				.lastName("")
				.password(passwordEncoder.encode(generateSecureRandomPassword()))
				.enabled(true)
				.build();

			RoleEntity userRole = roleRepository.findByName("ROLE_USER")
				.orElseThrow(() -> new ResourceNotFoundException("Role", "name: ROLE_USER"));
			newUser.addRole(userRole);

			UserEntity savedUser = userRepository.save(newUser);
			log.debug("Successfully saved OAuth user: {}", savedUser.getId());
			return savedUser;
		} catch (Exception e) {
			log.error("Error creating OAuth user: {}", e.getMessage(), e);
			throw new OAuthProcessingException("Failed to create user from OAuth data", e);
		}
	}

	/**
	 * Generates a unique username based on the given name.
	 * <p>
	 * Sanitizes the name and adds a counter if necessary to ensure uniqueness.
	 * </p>
	 *
	 * @param baseName The name to base the username on
	 * @return A unique username
	 */
	private String generateUniqueUsername(String baseName) {
		if (baseName == null || baseName.trim().isEmpty()) {
			baseName = "user";
		}

		String username = baseName.toLowerCase().replaceAll("[^a-z0-9]", "");
		if (username.length() < 3) {
			username = username + "user";
		}

		int counter = 0;
		String candidate = username;

		while (userRepository.findByUsername(candidate).isPresent()) {
			counter++;
			candidate = username + counter;
		}

		return candidate;
	}

	/**
	 * Generates a secure random password.
	 * <p>
	 * Creates a strong password for OAuth users who don't set their own password.
	 * </p>
	 *
	 * @return A strong random password
	 */
	private String generateSecureRandomPassword() {
		final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
		SecureRandom random = new SecureRandom();
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 16; i++) {
			int randomIndex = random.nextInt(chars.length());
			sb.append(chars.charAt(randomIndex));
		}
		return sb.toString();
	}

	// brute force protection methods

	/**
	 * Checks if a user account is currently locked out.
	 * <p>
	 * Part of the brute force protection mechanism to prevent
	 * repeated login attempts with wrong credentials.
	 * </p>
	 *
	 * @param identifier The username or email being used for login
	 * @throws AuthenticationException If the account is locked out
	 */
	private void checkLockoutStatus(String identifier) {
		LocalDateTime lockoutTime = lockoutTimes.get(identifier);
		if (lockoutTime != null) {
			if (LocalDateTime.now().isBefore(lockoutTime)) {
				long minutesRemaining = java.time.Duration.between(LocalDateTime.now(), lockoutTime).toMinutes() + 1;
				throw new AuthenticationException("Account temporarily locked. Try again in " + minutesRemaining + " minutes");
			} else {
				lockoutTimes.remove(identifier);
				loginAttempts.remove(identifier);
			}
		}
	}

	/**
	 * Records a failed login attempt for a user.
	 * <p>
	 * Increments the failed attempt counter and applies a lockout
	 * if the maximum number of attempts is reached.
	 * </p>
	 *
	 * @param identifier The username or email being used for login
	 */
	private void recordFailedLoginAttempt(String identifier) {
		int attempts = loginAttempts.getOrDefault(identifier, 0) + 1;
		loginAttempts.put(identifier, attempts);

		if (attempts >= MAX_ATTEMPTS) {
			int lockoutMinutes = Math.min(LOCKOUT_MINUTES * (1 << Math.min(attempts - MAX_ATTEMPTS, 2)), MAX_LOCKOUT_MINUTES);
			lockoutTimes.put(identifier, LocalDateTime.now().plusMinutes(lockoutMinutes));
			log.warn("Account locked for {} minutes due to {} failed login attempts: {}",
				lockoutMinutes, attempts, identifier);
		}
	}

	/**
	 * Cleans up expired login attempts and lockout records.
	 * <p>
	 * Scheduled task to prevent memory leaks from the login attempt tracking.
	 * </p>
	 */
	private void cleanupLoginAttempts() {
		lockoutTimes.entrySet().removeIf(entry -> LocalDateTime.now().isAfter(entry.getValue()));

		loginAttempts.entrySet().removeIf(entry -> !lockoutTimes.containsKey(entry.getKey()));

		log.debug("Cleaned up login attempts. Current tracking: {} attempts, {} lockouts",
			loginAttempts.size(), lockoutTimes.size());
	}

}
