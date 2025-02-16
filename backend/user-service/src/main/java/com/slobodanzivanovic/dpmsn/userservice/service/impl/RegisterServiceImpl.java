package com.slobodanzivanovic.dpmsn.userservice.service.impl;

import com.slobodanzivanovic.dpmsn.userservice.exception.UserAlreadyExistException;
import com.slobodanzivanovic.dpmsn.userservice.model.user.User;
import com.slobodanzivanovic.dpmsn.userservice.model.user.dto.request.RegisterRequest;
import com.slobodanzivanovic.dpmsn.userservice.model.user.entity.UserEntity;
import com.slobodanzivanovic.dpmsn.userservice.model.user.mapper.RegisterRequestToUserEntityMapper;
import com.slobodanzivanovic.dpmsn.userservice.model.user.mapper.UserEntityToUserMapper;
import com.slobodanzivanovic.dpmsn.userservice.repository.UserRepository;
import com.slobodanzivanovic.dpmsn.userservice.service.RegisterService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Implementation of {@link RegisterService} for handling user registration
 */
@Service
@RequiredArgsConstructor
public class RegisterServiceImpl implements RegisterService {

	private final UserRepository userRepository;

	private final RegisterRequestToUserEntityMapper registerRequestToUserEntityMapper = RegisterRequestToUserEntityMapper.initialize();

	private final UserEntityToUserMapper userEntityToUserMapper = UserEntityToUserMapper.initialize();

	private final PasswordEncoder passwordEncoder;

	/**
	 * Registers a new user based on the provided {@link RegisterRequest}
	 *
	 * <p>This method checks if the email already exists in the database, maps the registration request to a user entity,
	 * encodes the user's password, saves the user entity to the database, and returns the registered user</p>
	 *
	 * @param registerRequest the request containing user registration details
	 * @return the registered {@link User}
	 * @throws UserAlreadyExistException if the email is already used for another user
	 */
	@Override
	public User registerUser(RegisterRequest registerRequest) {

		if (userRepository.existsUserEntityByEmail(registerRequest.email())) {
			throw new UserAlreadyExistException("The email is already used for another admin : " + registerRequest.email());
		}

		final UserEntity userEntityToBeSave = registerRequestToUserEntityMapper.mapForSaving(registerRequest);

		userEntityToBeSave.setPassword(passwordEncoder.encode(registerRequest.password()));

		UserEntity savedUserEntity = userRepository.save(userEntityToBeSave);

		return userEntityToUserMapper.map(savedUserEntity);

	}

}
