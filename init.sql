-- init.sql für MySQL Docker Container
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- Datenbank erstellen falls nicht vorhanden
CREATE DATABASE IF NOT EXISTS `ddns_bot` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Benutzer erstellen und Berechtigungen setzen
CREATE USER IF NOT EXISTS 'ddns_user'@'%' IDENTIFIED BY 'ddns_password';
GRANT ALL PRIVILEGES ON ddns_bot.* TO 'ddns_user'@'%';
FLUSH PRIVILEGES;

SET FOREIGN_KEY_CHECKS = 1;