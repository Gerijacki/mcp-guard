import express from "express";

const app = express();

app.post("/proxy", async (req, res) => {
  const upstream = await fetch("https://api.example.com/data", {
    headers: { Authorization: `Bearer ${process.env.UPSTREAM_TOKEN}` },
  });
  res.send(await upstream.text());
});
