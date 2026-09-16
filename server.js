const express = require("express");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

// Serve files from the root folder
app.use(express.static(__dirname));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Open index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    message: "Tanzania Dating app is running"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Tanzania Dating running on port ${PORT}`);
});
