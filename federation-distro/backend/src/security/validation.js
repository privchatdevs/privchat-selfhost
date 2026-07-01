const { z } = require("zod");

const email = z
  .string()
  .trim()
  .email("Enter a valid email address.")
  .max(320, "Email is too long.")
  .transform((value) => value.toLowerCase());

// Strict rule for a NEW password (registration). Existing passwords are only ever
// checked against the stored hash, so login and password-confirmation use the
// lenient validator below: raising the minimum must never lock out an account
// created under the old 7-char rule.
const newPassword = z
  .string()
  .min(8, "Password needs to be at least 8 characters.")
  .max(128, "Password is too long.");

// Lenient: only bounds the length so a login / confirmation can't be empty or
// absurdly long. Correctness of the password itself is decided by argon2.verify.
const password = z
  .string()
  .min(1, "Enter your password.")
  .max(128, "Password is too long.");

const username = z
  .string()
  .trim()
  .min(4, "Username needs to be at least 4 characters.")
  .max(16, "Username cannot be more than 16 characters.")
  .regex(/^[A-Za-z0-9_.-]+$/, "Username can only use letters, numbers, dots, underscores, and dashes.");

const csrfToken = z.string().min(32, "Secure session expired. Refresh and try again.").max(96);
const hCaptchaResponse = z.string().min(1, "Please complete the captcha.").max(4096);
const profileAlias = z
  .string()
  .trim()
  .max(32, "Alias cannot be more than 32 characters.")
  .regex(/^[^\r\n\t]*$/, "Alias cannot contain line breaks or tabs.");

const loginSchema = z.object({
  email: z.string().trim().min(3, "Enter your email or username.").max(320).transform((value) => value.toLowerCase()),
  password,
  csrfToken,
  // Default true so a sign-in keeps you logged in (30-day persistent cookie)
  // even if the client doesn't send the flag.
  rememberMe: z.boolean().optional().default(true),
});

const registerSchema = z.object({
  username,
  email,
  password: newPassword,
  csrfToken,
  "h-captcha-response": hCaptchaResponse,
});

const profileSchema = z.object({
  alias: profileAlias,
  bio: z.string().trim().max(300, "About Me cannot be more than 300 characters.").optional().default(""),
  csrfToken,
});

const usernameUpdateSchema = z.object({
  username,
  password,
  csrfToken,
});

module.exports = { loginSchema, profileSchema, registerSchema, usernameUpdateSchema };
