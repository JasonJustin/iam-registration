const path = require("path");
const express = require("express");
const app = require("./server/app");

app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`\nIAM demo running: http://localhost:${PORT}\n`);
});
