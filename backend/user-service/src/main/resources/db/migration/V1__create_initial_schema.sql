CREATE TABLE users (
    id character varying(255) NOT NULL,
    created_at timestamp(6) without time zone,
    created_by character varying(255),
    updated_at timestamp(6) without time zone,
    updated_by character varying(255),
    email character varying(255),
    first_name character varying(255),
    last_name character varying(255),
    password character varying(255),
    phone_number character varying(20),
    user_status character varying(255),
    user_type character varying(255),
    CONSTRAINT users_pkey PRIMARY KEY (id),
    CONSTRAINT users_user_status_check CHECK (user_status::text = ANY (ARRAY['ACTIVE'::character varying, 'PASSIVE'::character varying, 'SUSPENDED'::character varying]::text[])),
    CONSTRAINT users_user_type_check CHECK (user_type::text = ANY (ARRAY['USER'::character varying, 'ADMIN'::character varying]::text[]))
);

CREATE TABLE invalid_token (
    id character varying(255) NOT NULL,
    created_at timestamp(6) without time zone,
    created_by character varying(255),
    updated_at timestamp(6) without time zone,
    updated_by character varying(255),
    token_id character varying(255),
    CONSTRAINT invalid_token_pkey PRIMARY KEY (id)
);
