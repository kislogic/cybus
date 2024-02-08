-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS `session`
(
    `token`      VARCHAR(300) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT 'Unique identifier of the session',
    `created_at` DATETIME                                                NOT NULL COMMENT 'When this record was created',
    `ip`         VARBINARY(16)                                           NOT NULL COMMENT 'Session ipv4 address',
    `user_id`    BIGINT                                                  NOT NULL COMMENT 'User ID',
    `platform`   VARCHAR(300) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL COMMENT 'User device platform',
    `place`      VARCHAR(300) CHARACTER SET utf8 COLLATE utf8_general_ci COMMENT 'Session start place',
    `disabled`   TINYINT                                                 NOT NULL DEFAULT 0 COMMENT 'Session is disabled',
    PRIMARY KEY (`token`),
    UNIQUE KEY `token_UNIQUE` (`token`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE `session`;
-- +goose StatementEnd
