const { config } = require("../config/env");

// Lazily create the SMTP transport so the app still boots if nodemailer or the
// SMTP config is missing - in that case verification codes are logged instead.
let transporter = null;
let transportReady = false;

function getTransporter() {
  if (transportReady) return transporter;
  transportReady = true;
  if (!config.smtp.host) {
    transporter = null;
    return null;
  }
  try {
    const nodemailer = require("nodemailer");
    const isLocal = /^(localhost|127\.0\.0\.1)$/.test(config.smtp.host);
    transporter = nodemailer.createTransport({
      host: config.smtp.host,
      port: config.smtp.port,
      secure: config.smtp.secure,
      auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.pass } : undefined,
      // A same-box Postfix relay has no auth and may offer only a self-signed
      // STARTTLS cert - don't reject it.
      ...(isLocal ? { tls: { rejectUnauthorized: false } } : {}),
    });
  } catch (error) {
    console.error("Email transport unavailable, falling back to logging codes:", error.message);
    transporter = null;
  }
  return transporter;
}

function verificationEmail(code) {
  const text = `Your PrivChat verification code is ${code}.\n\nIt expires in 15 minutes. If you did not create an account, you can ignore this email.`;
  const html = `
    <div style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#1e1f22; color:#f2f3f5; padding:32px; border-radius:12px; max-width:480px; margin:auto;">
      <h1 style="margin:0 0 8px; font-size:20px;">Confirm your email</h1>
      <p style="color:#b5bac1; margin:0 0 24px;">Use this code to finish creating your PrivChat account.</p>
      <div style="background:#111214; border-radius:10px; padding:18px; text-align:center; font-size:32px; font-weight:800; letter-spacing:8px;">${code}</div>
      <p style="color:#b5bac1; font-size:13px; margin:24px 0 0;">This code expires in 15 minutes. If you didn't sign up, you can safely ignore this email.</p>
    </div>`;
  return { text, html };
}

async function sendVerificationEmail(email, code) {
  const transport = getTransporter();
  if (!transport) {
    // Unconfigured: surface the code in the backend logs so the flow still works.
    console.log(`\x1b[36m[EMAIL]\x1b[0m No SMTP configured - verification code for ${email}: \x1b[1m${code}\x1b[0m`);
    return;
  }
  const { text, html } = verificationEmail(code);
  try {
    await transport.sendMail({
      from: config.smtp.from,
      to: email,
      subject: "Your PrivChat verification code",
      text,
      html,
    });
    console.log(`\x1b[36m[EMAIL]\x1b[0m Sent verification code to ${email}`);
  } catch (error) {
    // Never let an email failure block registration - log the code as a fallback.
    console.error(`\x1b[31m[EMAIL]\x1b[0m Failed to send to ${email}: ${error.message}`);
    console.log(`\x1b[36m[EMAIL]\x1b[0m Fallback verification code for ${email}: \x1b[1m${code}\x1b[0m`);
  }
}

// Sent when someone tries to REGISTER with an email that already has an account.
// Registration stays enumeration-safe (the API returns the same "check your email"
// response either way), so this note is what tells the real owner why no code came:
// they already have an account. It never contains a code or a one-click action.
function accountExistsEmail() {
  const text =
    `Someone just tried to create a PrivChat account with this email address, but ` +
    `you already have one.\n\n` +
    `If that was you, just sign in at ${config.publicUrl} - there's nothing to ` +
    `confirm. If you forgot your password, use "Forgot password" on the sign-in page.\n\n` +
    `If it wasn't you, you can safely ignore this email - no account was created or ` +
    `changed.\n\n- The PrivChat Team`;
  const html = `
    <div style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#1e1f22; color:#f2f3f5; padding:32px; border-radius:12px; max-width:480px; margin:auto;">
      <h1 style="margin:0 0 8px; font-size:20px;">You already have an account</h1>
      <p style="color:#b5bac1; margin:0 0 16px;">Someone just tried to create a PrivChat account with this email address, but you already have one.</p>
      <p style="color:#b5bac1; margin:0 0 16px;">If that was you, just <strong>sign in</strong> - there's nothing to confirm. Forgot your password? Use <strong>Forgot password</strong> on the sign-in page.</p>
      <p style="color:#6d7178; font-size:12px; margin:18px 0 0;">If it wasn't you, ignore this email - no account was created or changed.</p>
    </div>`;
  return { text, html };
}

async function sendAccountExistsEmail(email) {
  const transport = getTransporter();
  if (!transport) {
    console.log(`\x1b[36m[EMAIL]\x1b[0m No SMTP configured - would send "account exists" notice to ${email}`);
    return;
  }
  const { text, html } = accountExistsEmail();
  try {
    await transport.sendMail({
      from: config.smtp.from,
      to: email,
      subject: "You already have a PrivChat account",
      text,
      html,
    });
    console.log(`\x1b[36m[EMAIL]\x1b[0m Sent "account exists" notice to ${email}`);
  } catch (error) {
    // Never let this block the (enumeration-safe) registration response.
    console.error(`\x1b[31m[EMAIL]\x1b[0m Failed to send account-exists notice to ${email}: ${error.message}`);
  }
}

// Account-ban notice, sent right before an admin purges the account (so it still
// reaches the user's email before that row is deleted). Deliberately generic.
function banEmail(username) {
  const name = username ? username : "there";
  const text =
    `Hi ${name},\n\n` +
    `Your PrivChat account has been permanently suspended for violating our Terms of Service.\n\n` +
    `In keeping with our privacy-first design, your account and all associated data messages, ` +
    `DMs, servers, profile, minus login data have been permanently erased and ` +
    `cannot be recovered.\n\n` +
    `This action is final. You will not be able to sign in again.\n\n` +
    `- The PrivChat Team`;
  const html = `
    <div style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#1e1f22; color:#f2f3f5; padding:32px; border-radius:12px; max-width:480px; margin:auto;">
      <h1 style="margin:0 0 8px; font-size:20px;">Account suspended</h1>
      <p style="color:#b5bac1; margin:0 0 16px;">Hi ${name}, your PrivChat account has been <strong>permanently suspended</strong> for violating our Terms of Service.</p>
      <div style="background:#111214; border-left:3px solid #f0612b; border-radius:8px; padding:14px 16px; color:#dbdee1; font-size:14px; line-height:1.5;">
        In keeping with our privacy-first design, your account and all associated data messages, DMs, servers, profile, minus login data have been <strong>permanently erased</strong> and cannot be recovered.
      </div>
      <p style="color:#b5bac1; font-size:13px; margin:20px 0 0;">This action is final. You will not be able to sign in again.</p>
      <p style="color:#6d7178; font-size:12px; margin:18px 0 0;">- The PrivChat Team</p>
    </div>`;
  return { text, html };
}

async function sendBanEmail(email, username) {
  const transport = getTransporter();
  if (!transport) {
    console.log(`\x1b[36m[EMAIL]\x1b[0m No SMTP configured - would send ban notice to ${email}`);
    return;
  }
  const { text, html } = banEmail(username);
  try {
    await transport.sendMail({
      from: config.smtp.from,
      to: email,
      subject: "Your PrivChat account has been suspended",
      text,
      html,
    });
    console.log(`\x1b[36m[EMAIL]\x1b[0m Sent ban notice to ${email}`);
  } catch (error) {
    console.error(`\x1b[31m[EMAIL]\x1b[0m Failed to send ban notice to ${email}: ${error.message}`);
  }
}

// One-time visibility at startup so it's obvious whether real email is on.
if (config.smtp.host) {
  console.log(`\x1b[32m[EMAIL]\x1b[0m SMTP configured: ${config.smtp.host}:${config.smtp.port} (from ${config.smtp.from})`);
} else {
  console.log("\x1b[33m[EMAIL]\x1b[0m No SMTP configured - verification codes are logged here, not emailed. Set SMTP_* in backend/.env to send real email.");
}

// Generic sender for the admin panel's Mail compose. Throws NO_SMTP if email
// isn't configured (the admin UI surfaces that), instead of silently logging.
async function sendMail({ from, to, subject, text, html }) {
  const transport = getTransporter();
  if (!transport) {
    const err = new Error("SMTP is not configured.");
    err.code = "NO_SMTP";
    throw err;
  }
  return transport.sendMail({ from: from || config.smtp.from, to, subject, text, html });
}

module.exports = { sendVerificationEmail, sendAccountExistsEmail, sendBanEmail, sendMail };
