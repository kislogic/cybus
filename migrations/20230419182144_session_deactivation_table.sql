-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS `session`
(
    `created_at` DATETIME                                                NOT NULL COMMENT 'When this record was created',
    `ip`         VARBINARY(16)                                           NOT NULL COMMENT 'Session ipv4 address',
    `session_id` BIGINT                                                  NOT NULL COMMENT 'User ID'
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE `session`;
-- +goose StatementEnd
