// Vercel serverless entry point. Vercel rewrites all /api/* requests to
// this function; the Express app inside handles routing from there.
module.exports = require("../server/app");
