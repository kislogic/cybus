-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS `user`
(
    `id`            BIGINT       NOT NULL AUTO_INCREMENT COMMENT 'Unique identifier of the user',
    `created_at`    DATETIME     NOT NULL COMMENT 'When this record was created',
    `updated_at`    DATETIME     NOT NULL COMMENT 'When this record was last modified',
    `email`         VARCHAR(320) NOT NULL COMMENT 'User email',
    `phone`         VARCHAR(25)  NOT NULL COMMENT 'User phone',
    `full_name`     VARCHAR(45)  NOT NULL COMMENT 'User full name',
    `password_hash` BINARY(60)   NOT NULL COMMENT 'User password hash',
    `avatar`        VARCHAR(512) NOT NULL COMMENT 'User avatar link from file server',
    `is_banned`     TINYINT      NOT NULL DEFAULT '0',
    PRIMARY KEY (`id`),
    UNIQUE KEY `email_UNIQUE` (`email`),
    UNIQUE KEY `phone_UNIQUE` (`phone`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 30
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE `user`;
-- +goose StatementEnd
