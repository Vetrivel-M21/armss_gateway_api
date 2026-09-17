ALTER TABLE `portal_users` ADD COLUMN `role` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'user' AFTER `branch`;
UPDATE `portal_users` SET `role` = 'admin' WHERE `username` = 'admin';
