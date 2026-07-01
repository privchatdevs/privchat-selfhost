IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = N'auth')
BEGIN
  EXEC(N'CREATE SCHEMA auth');
END;
GO

CREATE TABLE auth.users (
  user_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_users_user_id DEFAULT NEWID(),
  public_user_id NVARCHAR(64) NULL,
  user_number BIGINT NULL,
  username NVARCHAR(16) NOT NULL,
  username_normalized AS LOWER(username) PERSISTED,
  email NVARCHAR(320) NOT NULL,
  email_normalized AS LOWER(email) PERSISTED,
  password_hash NVARCHAR(255) NOT NULL,
  encrypted_profile NVARCHAR(MAX) NULL,
  profile_alias NVARCHAR(32) NULL,
  bio NVARCHAR(300) NULL,
  profile_picture VARBINARY(MAX) NULL,
  profile_picture_mime NVARCHAR(32) NULL,
  profile_banner VARBINARY(MAX) NULL,
  profile_banner_mime NVARCHAR(32) NULL,
  failed_login_count INT NOT NULL CONSTRAINT DF_users_failed_login_count DEFAULT 0,
  locked_until DATETIME2(3) NULL,
  last_login_at DATETIME2(3) NULL,
  created_at DATETIME2(3) NOT NULL CONSTRAINT DF_users_created_at DEFAULT SYSUTCDATETIME(),
  updated_at DATETIME2(3) NOT NULL CONSTRAINT DF_users_updated_at DEFAULT SYSUTCDATETIME(),
  CONSTRAINT PK_users PRIMARY KEY CLUSTERED (user_id)
);
GO

CREATE UNIQUE INDEX UX_users_email_normalized
ON auth.users (email_normalized);
GO

CREATE UNIQUE INDEX UX_users_username_normalized
ON auth.users (username_normalized);
GO

CREATE UNIQUE INDEX UX_users_public_user_id
ON auth.users (public_user_id)
WHERE public_user_id IS NOT NULL;
GO

CREATE UNIQUE INDEX UX_users_user_number
ON auth.users (user_number)
WHERE user_number IS NOT NULL;
GO

CREATE TABLE auth.user_sessions (
  session_id UNIQUEIDENTIFIER NOT NULL CONSTRAINT DF_user_sessions_session_id DEFAULT NEWID(),
  user_id UNIQUEIDENTIFIER NOT NULL,
  token_hash VARBINARY(32) NOT NULL,
  expires_at DATETIME2(3) NOT NULL,
  revoked_at DATETIME2(3) NULL,
  ip_address NVARCHAR(45) NULL,
  user_agent NVARCHAR(512) NULL,
  created_at DATETIME2(3) NOT NULL CONSTRAINT DF_user_sessions_created_at DEFAULT SYSUTCDATETIME(),
  CONSTRAINT PK_user_sessions PRIMARY KEY CLUSTERED (session_id),
  CONSTRAINT FK_user_sessions_users FOREIGN KEY (user_id) REFERENCES auth.users(user_id) ON DELETE CASCADE
);
GO

CREATE UNIQUE INDEX UX_user_sessions_token_hash
ON auth.user_sessions (token_hash);
GO

CREATE INDEX IX_user_sessions_user_id_expires_at
ON auth.user_sessions (user_id, expires_at)
WHERE revoked_at IS NULL;
GO

CREATE TABLE auth.login_audit_log (
  audit_id BIGINT IDENTITY(1,1) NOT NULL,
  user_id UNIQUEIDENTIFIER NULL,
  email NVARCHAR(320) NULL,
  success BIT NOT NULL,
  ip_address NVARCHAR(45) NULL,
  user_agent NVARCHAR(512) NULL,
  created_at DATETIME2(3) NOT NULL CONSTRAINT DF_login_audit_log_created_at DEFAULT SYSUTCDATETIME(),
  CONSTRAINT PK_login_audit_log PRIMARY KEY CLUSTERED (audit_id),
  CONSTRAINT FK_login_audit_log_users FOREIGN KEY (user_id) REFERENCES auth.users(user_id)
);
GO

CREATE INDEX IX_login_audit_log_email_created_at
ON auth.login_audit_log (email, created_at DESC);
GO
