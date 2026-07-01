-- ============================================================
-- setup.sql  –  run once as sysadmin to bootstrap UntitledAuth
-- Usage:  sqlcmd -S localhost -E -i setup.sql
-- ============================================================

-- 1. Create the database (idempotent)
IF DB_ID(N'UntitledAuth') IS NULL
BEGIN
  CREATE DATABASE UntitledAuth;
  PRINT 'Database UntitledAuth created.';
END
ELSE
  PRINT 'Database UntitledAuth already exists – skipping CREATE DATABASE.';
GO

USE UntitledAuth;
GO

-- 2. Create the SQL login (idempotent)
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'app_login_user')
BEGIN
  CREATE LOGIN app_login_user WITH PASSWORD = N'AppLogin_S3cure!2024',
    DEFAULT_DATABASE = UntitledAuth,
    CHECK_EXPIRATION = OFF,
    CHECK_POLICY = ON;
  PRINT 'Login app_login_user created.';
END
ELSE
  PRINT 'Login app_login_user already exists – skipping CREATE LOGIN.';
GO

-- 3. Create the DB user mapped to the login (idempotent)
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'app_login_user')
BEGIN
  CREATE USER app_login_user FOR LOGIN app_login_user;
  PRINT 'DB user app_login_user created.';
END
ELSE
  PRINT 'DB user app_login_user already exists – skipping CREATE USER.';
GO

-- 4. Create the auth schema (idempotent)
IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = N'auth')
BEGIN
  EXEC(N'CREATE SCHEMA auth AUTHORIZATION dbo');
  PRINT 'Schema auth created.';
END
ELSE
  PRINT 'Schema auth already exists – skipping CREATE SCHEMA.';
GO

-- 5. Create tables (idempotent)
IF OBJECT_ID(N'auth.users', 'U') IS NULL
BEGIN
  CREATE TABLE auth.users (
    user_id               UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_users_user_id DEFAULT NEWID(),
    public_user_id        NVARCHAR(64)     NULL,
    user_number           BIGINT           NULL,
    username              NVARCHAR(16)     NOT NULL,
    username_normalized   AS LOWER(username) PERSISTED,
    email                 NVARCHAR(320)    NOT NULL,
    email_normalized      AS LOWER(email)  PERSISTED,
    password_hash         NVARCHAR(255)    NOT NULL,
    encrypted_profile     NVARCHAR(MAX)    NULL,
    profile_alias         NVARCHAR(32)     NULL,
    bio                   NVARCHAR(300)    NULL,
    profile_picture       VARBINARY(MAX)   NULL,
    profile_picture_mime  NVARCHAR(32)     NULL,
    profile_banner        VARBINARY(MAX)   NULL,
    profile_banner_mime   NVARCHAR(32)     NULL,
    failed_login_count    INT              NOT NULL CONSTRAINT DF_users_failed_login_count DEFAULT 0,
    locked_until          DATETIME2(3)     NULL,
    last_login_at         DATETIME2(3)     NULL,
    created_at            DATETIME2(3)     NOT NULL CONSTRAINT DF_users_created_at DEFAULT SYSUTCDATETIME(),
    updated_at            DATETIME2(3)     NOT NULL CONSTRAINT DF_users_updated_at DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_users PRIMARY KEY CLUSTERED (user_id)
  );
  PRINT 'Table auth.users created.';
END
ELSE
  PRINT 'Table auth.users already exists – skipping.';
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_users_email_normalized' AND object_id = OBJECT_ID(N'auth.users'))
  CREATE UNIQUE INDEX UX_users_email_normalized ON auth.users (email_normalized);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_users_username_normalized' AND object_id = OBJECT_ID(N'auth.users'))
  CREATE UNIQUE INDEX UX_users_username_normalized ON auth.users (username_normalized);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_users_public_user_id' AND object_id = OBJECT_ID(N'auth.users'))
  CREATE UNIQUE INDEX UX_users_public_user_id ON auth.users (public_user_id) WHERE public_user_id IS NOT NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_users_user_number' AND object_id = OBJECT_ID(N'auth.users'))
  CREATE UNIQUE INDEX UX_users_user_number ON auth.users (user_number) WHERE user_number IS NOT NULL;
GO

IF OBJECT_ID(N'auth.user_sessions', 'U') IS NULL
BEGIN
  CREATE TABLE auth.user_sessions (
    session_id  UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_user_sessions_session_id DEFAULT NEWID(),
    user_id     UNIQUEIDENTIFIER NOT NULL,
    token_hash  VARBINARY(32)    NOT NULL,
    expires_at  DATETIME2(3)     NOT NULL,
    revoked_at  DATETIME2(3)     NULL,
    ip_address  NVARCHAR(45)     NULL,
    user_agent  NVARCHAR(512)    NULL,
    created_at  DATETIME2(3)     NOT NULL CONSTRAINT DF_user_sessions_created_at DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_user_sessions PRIMARY KEY CLUSTERED (session_id),
    CONSTRAINT FK_user_sessions_users FOREIGN KEY (user_id) REFERENCES auth.users(user_id) ON DELETE CASCADE
  );
  PRINT 'Table auth.user_sessions created.';
END
ELSE
  PRINT 'Table auth.user_sessions already exists – skipping.';
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_user_sessions_token_hash' AND object_id = OBJECT_ID(N'auth.user_sessions'))
  CREATE UNIQUE INDEX UX_user_sessions_token_hash ON auth.user_sessions (token_hash);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_user_sessions_user_id_expires_at' AND object_id = OBJECT_ID(N'auth.user_sessions'))
  CREATE INDEX IX_user_sessions_user_id_expires_at ON auth.user_sessions (user_id, expires_at) WHERE revoked_at IS NULL;
GO

IF OBJECT_ID(N'auth.login_audit_log', 'U') IS NULL
BEGIN
  CREATE TABLE auth.login_audit_log (
    audit_id    BIGINT           IDENTITY(1,1) NOT NULL,
    user_id     UNIQUEIDENTIFIER NULL,
    email       NVARCHAR(320)    NULL,
    success     BIT              NOT NULL,
    ip_address  NVARCHAR(45)     NULL,
    user_agent  NVARCHAR(512)    NULL,
    created_at  DATETIME2(3)     NOT NULL CONSTRAINT DF_login_audit_log_created_at DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_login_audit_log PRIMARY KEY CLUSTERED (audit_id),
    CONSTRAINT FK_login_audit_log_users FOREIGN KEY (user_id) REFERENCES auth.users(user_id)
  );
  PRINT 'Table auth.login_audit_log created.';
END
ELSE
  PRINT 'Table auth.login_audit_log already exists – skipping.';
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_login_audit_log_email_created_at' AND object_id = OBJECT_ID(N'auth.login_audit_log'))
  CREATE INDEX IX_login_audit_log_email_created_at ON auth.login_audit_log (email, created_at DESC);
GO

-- 6. Grant permissions to app_login_user
GRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::auth TO app_login_user;
PRINT 'Permissions granted to app_login_user on schema auth.';
GO

PRINT '';
PRINT '=== Setup complete ===';
PRINT 'Update backend\.env:  SQL_PASSWORD=AppLogin_S3cure!2024';
GO
