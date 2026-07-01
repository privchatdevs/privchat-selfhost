IF COL_LENGTH('auth.users', 'username') IS NULL
BEGIN
  ALTER TABLE auth.users
  ADD username NVARCHAR(32) NULL;
END;
GO

UPDATE auth.users
SET username = LEFT(REPLACE(email, '@', '_'), 32)
WHERE username IS NULL;
GO

ALTER TABLE auth.users
ALTER COLUMN username NVARCHAR(32) NOT NULL;
GO

IF COL_LENGTH('auth.users', 'username_normalized') IS NULL
BEGIN
  ALTER TABLE auth.users
  ADD username_normalized AS LOWER(username) PERSISTED;
END;
GO

IF NOT EXISTS (
  SELECT 1
  FROM sys.indexes
  WHERE name = N'UX_users_username_normalized'
    AND object_id = OBJECT_ID(N'auth.users')
)
BEGIN
  CREATE UNIQUE INDEX UX_users_username_normalized
  ON auth.users (username_normalized);
END;
GO
