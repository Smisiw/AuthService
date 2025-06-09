CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE TABLE IF NOT EXISTS roles (
                                     id          uuid PRIMARY KEY default gen_random_uuid(),
                                     "name" VARCHAR(50) UNIQUE NOT NULL
    );

INSERT INTO roles VALUES ('d7fbaa51-d73c-4e4f-8bd1-a6a727a67dbe','ROLE_USER'), ('94262bc5-184e-40a6-8990-d9811439739b','ROLE_SELLER'), ('a2f627ab-f6f5-4b80-90ad-531916f2ca6b','ROLE_ADMIN')
    ON CONFLICT DO NOTHING;
INSERT INTO users values ('0b32c802-2579-4e0f-bab7-9c95ce23698e', '$2y$10$.p3EuL9iQLQsqKEV.jWYseaMrvhtXyUh1IbWMtaYCFFV8Mq7RUWGG', 'user'),
                         ('24da571a-8ca1-42aa-a650-133dffea4197', '$2y$10$.p3EuL9iQLQsqKEV.jWYseaMrvhtXyUh1IbWMtaYCFFV8Mq7RUWGG', 'seller'),
                         ('89e7b0af-924b-4541-8c0f-87322273ab59', '$2y$10$.p3EuL9iQLQsqKEV.jWYseaMrvhtXyUh1IbWMtaYCFFV8Mq7RUWGG', 'admin');
INSERT INTO user_roles values ('0b32c802-2579-4e0f-bab7-9c95ce23698e', 'd7fbaa51-d73c-4e4f-8bd1-a6a727a67dbe'),
                              ('24da571a-8ca1-42aa-a650-133dffea4197', '94262bc5-184e-40a6-8990-d9811439739b'),
                              ('89e7b0af-924b-4541-8c0f-87322273ab59', 'a2f627ab-f6f5-4b80-90ad-531916f2ca6b');