ALTER TABLE `portal_users`
  ADD COLUMN `branch` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '' AFTER `department`;