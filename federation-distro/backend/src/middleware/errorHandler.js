function notFoundHandler(_req, res) {
  res.status(404).json({ message: "Not found." });
}

function getSqlMessage(error) {
  const message = error.message || "";

  if (/failed to connect|could not connect|econnrefused|etimeout/i.test(message)) {
    return {
      statusCode: 500,
      message: "Failed to securely connect to database.",
    };
  }

  if (/login failed for user/i.test(message)) {
    return {
      statusCode: 500,
      message: "Database login failed. Check SQL_USER and SQL_PASSWORD in backend/.env.",
    };
  }

  if (error.number === 207 && /username/i.test(message)) {
    return {
      statusCode: 500,
      message: "Database needs the username migration before registration can work.",
    };
  }

  if ((error.number === 2601 || error.number === 2627) && /username/i.test(message)) {
    return {
      statusCode: 409,
      message: "Username is taken.",
    };
  }

  if ((error.number === 2601 || error.number === 2627) && /email/i.test(message)) {
    return {
      statusCode: 409,
      message: "Email is already in use.",
    };
  }

  return null;
}

function errorHandler(error, _req, res, _next) {
  if (error.name === "ZodError") {
    return res.status(400).json({ message: error.issues[0]?.message || "Invalid request." });
  }

  if (error.type === "entity.too.large") {
    return res.status(413).json({ message: "Profile picture cannot be over 5 MB." });
  }

  if (error.statusCode) {
    return res.status(error.statusCode).json({ message: error.message });
  }

  if (error.status) {
    return res.status(error.status).json({ message: error.message || "Invalid request." });
  }

  const sqlMessage = getSqlMessage(error);
  if (sqlMessage) {
    return res.status(sqlMessage.statusCode).json({ message: sqlMessage.message });
  }

  if (process.env.NODE_ENV !== "production") {
    console.error(error);
    return res.status(500).json({ message: error.message || "Server error." });
  }

  console.error(error);
  return res.status(500).json({ message: "Something went wrong." });
}

module.exports = { errorHandler, notFoundHandler };
