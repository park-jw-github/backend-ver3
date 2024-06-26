-- 데이터베이스 생성 및 설정
-- CREATE SCHEMA IF NOT EXISTS `testdb` DEFAULT CHARACTER SET utf8mb4;

-- root 사용자 생성 및 권한 부여
-- CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY 'root';
-- GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
-- FLUSH PRIVILEGES;

-- 'testdb' 스키마 선택
-- USE testdb;

-- 데이터베이스 생성 및 설정
CREATE SCHEMA IF NOT EXISTS `testdb`;

-- User 테이블 생성
CREATE TABLE IF NOT EXISTS UUser (
id INT AUTO_INCREMENT PRIMARY KEY,
email VARCHAR(255) NOT NULL UNIQUE,
password VARCHAR(255) NOT NULL
);

-- Resume 테이블 생성
CREATE TABLE IF NOT EXISTS RResume (
id INT AUTO_INCREMENT PRIMARY KEY,
user_id INT NOT NULL,
title TEXT,
created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
FOREIGN KEY (user_id) REFERENCES UUser(id) ON DELETE CASCADE
);

-- Skill 테이블 생성
CREATE TABLE IF NOT EXISTS SSkill (
id INT AUTO_INCREMENT PRIMARY KEY,
resume_id INT NOT NULL,
status BOOLEAN DEFAULT FALSE,
tech_stack VARCHAR(100) DEFAULT NULL,
content TEXT DEFAULT NULL,
FOREIGN KEY (resume_id) REFERENCES RResume(id) ON DELETE CASCADE
);

-- Career 테이블 생성
CREATE TABLE IF NOT EXISTS CCareer (
id INT AUTO_INCREMENT PRIMARY KEY,
resume_id INT NOT NULL,
status BOOLEAN DEFAULT FALSE,
company TEXT DEFAULT NULL,
department TEXT DEFAULT NULL,
period VARCHAR(100) DEFAULT NULL,
is_current BOOLEAN DEFAULT NULL,
tech_stack VARCHAR(100) DEFAULT NULL,
content TEXT DEFAULT NULL,
FOREIGN KEY (resume_id) REFERENCES RResume(id) ON DELETE CASCADE
);

-- Project 테이블 생성
CREATE TABLE IF NOT EXISTS PProject (
id INT AUTO_INCREMENT PRIMARY KEY,
resume_id INT NOT NULL,
status BOOLEAN DEFAULT FALSE,
title TEXT DEFAULT NULL,
period VARCHAR(100) DEFAULT NULL,
is_current BOOLEAN DEFAULT NULL,
intro TEXT DEFAULT NULL,
tech_stack VARCHAR(100) DEFAULT NULL,
content TEXT DEFAULT NULL,
FOREIGN KEY (resume_id) REFERENCES RResume(id) ON DELETE CASCADE
);