package com.slobodanzivanovic.dpmsn.core.model.auth.entity;

import com.slobodanzivanovic.dpmsn.core.model.common.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "roles")
@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
@ToString(exclude = "users")
public class RoleEntity extends BaseEntity {

	@Column(name = "name", nullable = false, unique = true)
	private String name;

	@Column(name = "status", nullable = false)
	@lombok.Builder.Default
	private boolean status = true;

	@ManyToMany(mappedBy = "roles")
	@lombok.Builder.Default
	private Set<UserEntity> users = new HashSet<>();
}
