CREATE TABLE IF NOT EXISTS public.roles
(
	id         uuid PRIMARY KEY,
	name       VARCHAR(255) NOT NULL UNIQUE,
	status     BOOLEAN      NOT NULL,
	created_at TIMESTAMP(6) WITHOUT TIME ZONE,
	updated_at TIMESTAMP(6) WITHOUT TIME ZONE,
	created_by VARCHAR(255),
	updated_by VARCHAR(255),
	version    BIGINT
);

CREATE TABLE IF NOT EXISTS public.users
(
	id                           uuid PRIMARY KEY,
	username                     VARCHAR(50)  NOT NULL UNIQUE,
	first_name                   VARCHAR(50)  NOT NULL,
	last_name                    VARCHAR(50)  NOT NULL,
	email                        VARCHAR(100) NOT NULL UNIQUE,
	password                     VARCHAR(255) NOT NULL,
	phone_number                 VARCHAR(255),
	birth_date                   DATE,
	verification_code            VARCHAR(255),
	verification_code_expires_at TIMESTAMP(6) WITHOUT TIME ZONE,
	enabled                      BOOLEAN      NOT NULL,
	created_at                   TIMESTAMP(6) WITHOUT TIME ZONE,
	updated_at                   TIMESTAMP(6) WITHOUT TIME ZONE,
	created_by                   VARCHAR(255),
	updated_by                   VARCHAR(255),
	version                      BIGINT
);

CREATE TABLE IF NOT EXISTS public.user_roles
(
	user_id uuid NOT NULL,
	role_id uuid NOT NULL,
	PRIMARY KEY (user_id, role_id),
	CONSTRAINT fkhfh9dx7w3ubf1co1vdev94g3f FOREIGN KEY (user_id) REFERENCES public.users (id),
	CONSTRAINT fkh8ciramu9cc9q3qcqiv4ue8a6 FOREIGN KEY (role_id) REFERENCES public.roles (id)
);

INSERT INTO public.roles (id, name, status, created_at, updated_at, version)
VALUES (gen_random_uuid(), 'ROLE_USER', true, NOW(), NOW(), 0),
	   (gen_random_uuid(), 'ROLE_ADMIN', true, NOW(), NOW(), 0);
