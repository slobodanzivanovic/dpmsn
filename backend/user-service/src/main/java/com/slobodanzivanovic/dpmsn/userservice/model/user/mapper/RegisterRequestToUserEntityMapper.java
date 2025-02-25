package com.slobodanzivanovic.dpmsn.userservice.model.user.mapper;

import com.slobodanzivanovic.dpmsn.userservice.model.common.mapper.BaseMapper;
import com.slobodanzivanovic.dpmsn.userservice.model.user.dto.request.RegisterRequest;
import com.slobodanzivanovic.dpmsn.userservice.model.user.entity.UserEntity;
import com.slobodanzivanovic.dpmsn.userservice.model.user.enums.UserType;
import org.mapstruct.Mapper;
import org.mapstruct.Named;
import org.mapstruct.factory.Mappers;

/**
 * Mapper interface for converting between {@link RegisterRequest} and {@link UserEntity}
 * This mapper handles the transformation of user registration request data into a user entity
 * for persistence in the database.
 */
@Mapper
public interface RegisterRequestToUserEntityMapper extends BaseMapper<RegisterRequest, UserEntity> {

	/**
	 * Maps a {@link RegisterRequest} to a {@link UserEntity} for saving
	 * This method maps the user's registration request to a {@link UserEntity} with appropriate
	 * user type based on the role specified in the request
	 *
	 * @param userRegisterRequest the registration request containing user details
	 * @return a {@link UserEntity} with mapped values
	 */
	@Named("mapForSaving")
	default UserEntity mapForSaving(RegisterRequest userRegisterRequest) {

		UserType userType = "admin".equalsIgnoreCase(userRegisterRequest.role()) ? UserType.ADMIN : UserType.USER;

		return UserEntity.builder()
			.email(userRegisterRequest.email())
			.firstName(userRegisterRequest.firstName())
			.lastName(userRegisterRequest.lastName())
			.phoneNumber(userRegisterRequest.phoneNumber())
			.userType(userType)
			.build();
	}

	/**
	 * Initializes the {@link RegisterRequestToUserEntityMapper} mapper
	 *
	 * @return a new instance of {@link RegisterRequestToUserEntityMapper}
	 */
	static RegisterRequestToUserEntityMapper initialize() {
		return Mappers.getMapper(RegisterRequestToUserEntityMapper.class);
	}

}
