import express from "express";

const app = express();

app.post("/proxy", async (req, res) => {
  const upstream = await fetch("https://api.example.com/data", {
    headers: { Authorization: req.headers.authorization as string },
  });
  res.send(await upstream.text());
});
