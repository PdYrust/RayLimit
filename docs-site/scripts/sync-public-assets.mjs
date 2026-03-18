import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import React from "react";
import { ImageResponse } from "next/og.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repositoryRoot = path.resolve(__dirname, "..", "..");
const publicDir = path.resolve(__dirname, "..", "public");

const assetMap = [
  ["assets/logo/raylimit-icon.svg", "raylimit-icon.svg"],
  ["assets/logo/raylimit-icon.png", "raylimit-icon.png"],
];

fs.mkdirSync(publicDir, { recursive: true });

for (const [sourceRelative, targetName] of assetMap) {
  const source = path.resolve(repositoryRoot, sourceRelative);
  const target = path.resolve(publicDir, targetName);

  if (!fs.existsSync(source)) {
    throw new Error(`Missing asset source: ${sourceRelative}`);
  }

  fs.copyFileSync(source, target);
}

const previewTarget = path.resolve(publicDir, "og-preview.png");
const previewImage = new ImageResponse(
  React.createElement(
    "div",
    {
      style: {
        width: "100%",
        height: "100%",
        display: "flex",
        background: "#ffffff",
        color: "#09090b",
        padding: "52px",
        fontFamily: "sans-serif",
      },
    },
    React.createElement(
      "div",
      {
        style: {
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          borderRadius: "34px",
          border: "1px solid #e4e4e7",
          background: "#ffffff",
          padding: "54px",
        },
      },
      React.createElement(
        "div",
        {
          style: {
            display: "flex",
            alignItems: "center",
          },
        },
        React.createElement(
          "div",
          {
            style: {
              display: "flex",
              width: "132px",
              height: "132px",
              alignItems: "center",
              justifyContent: "center",
              borderRadius: "30px",
              border: "2px solid #111111",
              fontSize: "54px",
              fontWeight: 700,
              letterSpacing: "-0.08em",
            },
          },
          "{x}"
        ),
        React.createElement(
          "div",
          {
            style: {
              display: "flex",
              flexDirection: "column",
              marginLeft: "28px",
            },
          },
          React.createElement(
            "div",
            {
              style: {
                display: "flex",
                fontSize: "70px",
                fontWeight: 700,
                letterSpacing: "-0.08em",
                lineHeight: 1,
              },
            },
            "RayLimit"
          ),
          React.createElement(
            "div",
            {
              style: {
                display: "flex",
                marginTop: "10px",
                fontSize: "28px",
                color: "#52525b",
                letterSpacing: "-0.03em",
              },
            },
            "Documentation"
          )
        )
      ),
      React.createElement(
        "div",
        {
          style: {
            display: "flex",
            flexDirection: "column",
            maxWidth: "920px",
          },
        },
        React.createElement(
          "div",
          {
            style: {
              display: "flex",
              fontSize: "54px",
              fontWeight: 700,
              letterSpacing: "-0.06em",
              lineHeight: 1.02,
            },
          },
          "Reconcile-aware traffic shaping for Xray runtimes on Linux."
        ),
        React.createElement(
          "div",
          {
            style: {
              display: "flex",
              marginTop: "18px",
              fontSize: "28px",
              color: "#52525b",
              lineHeight: 1.45,
              letterSpacing: "-0.02em",
            },
          },
          "Discover runtime state, inspect the live target, and apply guarded speed limiters with dry-run-first workflows."
        )
      ),
      React.createElement(
        "div",
        {
          style: {
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          },
        },
        React.createElement(
          "div",
          {
            style: {
              display: "flex",
              fontSize: "24px",
              color: "#27272a",
              letterSpacing: "-0.02em",
            },
          },
          "Installation · Common commands · Speed limiters · Internals"
        ),
        React.createElement(
          "div",
          {
            style: {
              display: "flex",
              fontSize: "22px",
              color: "#52525b",
              letterSpacing: "-0.02em",
            },
          },
          "pdyrust.github.io/RayLimit"
        )
      )
    )
  ),
  { width: 1200, height: 630 }
);

const previewBuffer = await previewImage.arrayBuffer();
fs.writeFileSync(previewTarget, Buffer.from(previewBuffer));
