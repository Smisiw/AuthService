CREATE TABLE IF NOT EXISTS roles (
                                     id SERIAL PRIMARY KEY,
                                     "name" VARCHAR(50) UNIQUE NOT NULL
    );

INSERT INTO roles (name) VALUES ('ROLE_USER'), ('ROLE_SELLER'), ('ROLE_ADMIN')
    ON CONFLICT (name) DO NOTHING;