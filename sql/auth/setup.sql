-- DROP SCHEMA auth;

CREATE SCHEMA auth AUTHORIZATION postgres;
-- auth.orgs definition

-- Drop table

-- DROP TABLE orgs;

CREATE TABLE orgs (
	id varchar(64) NOT NULL,
	created_at timestamp NULL,
	updated_at timestamp NULL,
	hash_config json NULL,
	CONSTRAINT orgs_pkey PRIMARY KEY (id)
);


-- auth.roles definition

-- Drop table

-- DROP TABLE roles;

CREATE TABLE roles (
	id varchar(64) NOT NULL,
	created_at timestamp NULL,
	updated_at timestamp NULL,
	CONSTRAINT roles_pkey PRIMARY KEY (id)
);


-- auth.services definition

-- Drop table

-- DROP TABLE services;

CREATE TABLE services (
	"name" varchar(64) NOT NULL,
	icon_path varchar(64) NULL,
	"path" varchar(64) NULL,
	CONSTRAINT services_pkey PRIMARY KEY (name)
);


-- auth.hosts definition

-- Drop table

-- DROP TABLE hosts;

CREATE TABLE hosts (
	id varchar(64) NOT NULL,
	hostname varchar(64) NULL,
	ip varchar(64) NULL,
	port int4 NULL,
	service varchar(64) NULL,
	CONSTRAINT hosts_pkey PRIMARY KEY (id),
	CONSTRAINT hosts_service_fkey FOREIGN KEY (service) REFERENCES services("name")
);


-- auth.sessions definition

-- Drop table

-- DROP TABLE sessions;

CREATE TABLE sessions (
	id varchar(64) NOT NULL,
	created_at timestamp NULL,
	jwt varchar(2048) NULL,
	expires_at timestamp NULL,
	user_id varchar(64) NULL,
	pub_key bytea NULL,
	CONSTRAINT sessions_pkey PRIMARY KEY (id)
);


-- auth.teams definition

-- Drop table

-- DROP TABLE teams;

CREATE TABLE teams (
	id varchar(64) NOT NULL,
	created_at timestamp NULL,
	updated_at timestamp NULL,
	"owner" varchar(64) NULL,
	org_id varchar(64) NULL,
	CONSTRAINT teams_pkey PRIMARY KEY (id)
);


-- auth.users definition

-- Drop table

-- DROP TABLE users;

CREATE TABLE users (
	id varchar(64) NOT NULL,
	username varchar(64) NULL,
	role_id varchar(64) NULL,
	"password" varchar(128) NULL,
	email varchar(64) NULL,
	created_at timestamp NULL,
	updated_at timestamp NULL,
	team_id varchar(64) NULL,
	org_id varchar(64) NULL,
	active bool NULL,
	CONSTRAINT users_pkey PRIMARY KEY (id)
);


-- auth.sessions foreign keys

ALTER TABLE auth.sessions ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id);


-- auth.teams foreign keys

ALTER TABLE auth.teams ADD CONSTRAINT teams_org_id_fkey FOREIGN KEY (org_id) REFERENCES orgs(id);
ALTER TABLE auth.teams ADD CONSTRAINT teams_owner_fkey FOREIGN KEY ("owner") REFERENCES users(id);


-- auth.users foreign keys

ALTER TABLE auth.users ADD CONSTRAINT users_org_id_fkey FOREIGN KEY (org_id) REFERENCES orgs(id);
ALTER TABLE auth.users ADD CONSTRAINT users_role_id_fkey FOREIGN KEY (role_id) REFERENCES roles(id);
ALTER TABLE auth.users ADD CONSTRAINT users_team_id_fkey FOREIGN KEY (team_id) REFERENCES teams(id);
