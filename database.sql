-- Adminer 4.7.1 MySQL dump

SET NAMES utf8;
SET time_zone = '+00:00';
SET foreign_key_checks = 0;
SET sql_mode = 'NO_AUTO_VALUE_ON_ZERO';

USE `hcs`;

DROP TABLE IF EXISTS `board`;
CREATE TABLE `board` (
  `idx` int(11) NOT NULL AUTO_INCREMENT,
  `postedtime` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lasttime` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `author` int(11) NOT NULL DEFAULT '0',
  `replyto` int(11) NOT NULL DEFAULT '0',
  `subject` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `message` text COLLATE utf8_unicode_ci,
  `ip` varchar(15) COLLATE utf8_unicode_ci DEFAULT NULL,
  KEY `idx` (`idx`),
  KEY `replyto` (`replyto`),
  KEY `author` (`author`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `idx` int(11) NOT NULL AUTO_INCREMENT,
  `joined` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `uname` varchar(31) COLLATE utf8_unicode_ci NOT NULL DEFAULT '',
  `pass_hash` varchar(9999) COLLATE utf8_unicode_ci NOT NULL DEFAULT '',
  `lastlogin` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `prevlogin` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `logintoken` varchar(32) COLLATE utf8_unicode_ci NOT NULL DEFAULT '',
  `postcount` int(11) NOT NULL DEFAULT '0',
  KEY `idx` (`idx`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


-- 2019-03-31 17:50:29
