ALTER TABLE `installer_otp_requests`
  ADD COLUMN `username` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL AFTER `id`,
  ADD COLUMN `department` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL AFTER `username`,
  ADD COLUMN `branch` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL AFTER `department`;