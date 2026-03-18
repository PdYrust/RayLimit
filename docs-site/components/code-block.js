"use client";

import { useEffect, useState } from "react";
import { CheckIcon, CopyIcon } from "./ui-icons";

async function copyText(value) {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }

  if (typeof document === "undefined") {
    throw new Error("Clipboard is unavailable.");
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "absolute";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  document.body.removeChild(textarea);
}

export function CodeBlock({ value, language }) {
  const [status, setStatus] = useState("idle");

  useEffect(() => {
    if (status !== "copied") {
      return undefined;
    }

    const timeout = window.setTimeout(() => {
      setStatus("idle");
    }, 1800);

    return () => window.clearTimeout(timeout);
  }, [status]);

  async function handleCopy() {
    try {
      await copyText(value);
      setStatus("copied");
    } catch {
      setStatus("error");
      window.setTimeout(() => {
        setStatus("idle");
      }, 1800);
    }
  }

  const label = status === "copied" ? "Copied" : status === "error" ? "Retry" : "Copy";

  return (
    <div className="code-block-shell">
      {language ? <span className="code-block-language">{language}</span> : null}
      <button
        type="button"
        className={status === "copied" ? "code-copy-button copied" : "code-copy-button"}
        onClick={handleCopy}
        aria-label={`${label} code block`}
      >
        {status === "copied" ? <CheckIcon /> : <CopyIcon />}
        <span>{label}</span>
      </button>
      <pre className="code-block">
        <code>{value}</code>
      </pre>
    </div>
  );
}
