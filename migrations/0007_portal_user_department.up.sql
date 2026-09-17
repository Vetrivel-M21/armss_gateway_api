ALTER TABLE `portal_users`
  ADD COLUMN `department` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' AFTER `full_name`;
