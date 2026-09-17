CREATE TABLE `portal_user_otp_requests` (
  `id` varchar(36) NOT NULL,
  `user_id` bigint unsigned NOT NULL,
  `purpose` enum('PASSWORD_RESET') COLLATE utf8mb4_unicode_ci NOT NULL,
  `otp_code` varchar(6) COLLATE utf8mb4_unicode_ci NOT NULL,
  `expires_at` datetime(3) NOT NULL,
  `verified` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_portal_user_otp_user` (`user_id`),
  CONSTRAINT `fk_portal_user_otp_user` FOREIGN KEY (`user_id`) REFERENCES `portal_users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
