package com.slobodanzivanovic.dpmsn.core.model.auth.entity;

import com.slobodanzivanovic.dpmsn.core.model.common.entity.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
public class UserEntity extends BaseEntity {

	@NotBlank
	@Size(min = 3, max = 50)
	@Column(name = "username", unique = true, nullable = false)
	private String username;

	@NotBlank
	@Size(max = 50)
	@Column(name = "first_name", nullable = false)
	private String firstName;

	@NotBlank
	@Size(max = 50)
	@Column(name = "last_name", nullable = false)
	private String lastName;

	@Email
	@NotBlank
	@Size(max = 100)
	@Column(name = "email", unique = true, nullable = false)
	private String email;

	@NotBlank
	@Column(name = "password", nullable = false)
	private String password;

	@Column(name = "phone_number")
	private String phoneNumber;

	@Column(name = "birth_date")
	private LocalDate birthDate;

	@Column(name = "verification_code")
	private String verificationCode;

	@Column(name = "verification_code_expires_at")
	private LocalDateTime verificationCodeExpiresAt;

	@Column(name = "enabled", nullable = false)
	@lombok.Builder.Default
	private boolean enabled = false;

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "user_roles",
		joinColumns = @JoinColumn(name = "user_id"),
		inverseJoinColumns = @JoinColumn(name = "role_id"))
	@lombok.Builder.Default
	private Set<RoleEntity> roles = new HashSet<>();

	// helper methods for bidirectional relationship
	public void addRole(RoleEntity role) {
		roles.add(role);
		role.getUsers().add(this);
	}

	public void removeRole(RoleEntity role) {
		roles.remove(role);
		role.getUsers().remove(this);
	}

}
