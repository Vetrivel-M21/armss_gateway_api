ALTER TABLE `portal_users` ADD COLUMN `bound_device_id` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' AFTER `role`;
ALTER TABLE `portal_users` ADD COLUMN `active_session_token` varchar(512) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' AFTER `bound_device_id`;
ALTER TABLE `portal_users` ADD COLUMN `last_login_at` datetime NULL AFTER `active_session_token`;
