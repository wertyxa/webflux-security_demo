CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY ,
    username VARCHAR(64) NOT NULL UNIQUE ,
    password VARCHAR(2048) NOT NULL ,
    role VARCHAR(32) NOT NULL ,
    first_name varchar(64) not null ,
    last_name varchar(64) not null ,
    enabled boolean not null default false,
    created_at timestamp not null,
    updated_at timestamp not null
);