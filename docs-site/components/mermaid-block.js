"use client";

import { useEffect, useId, useState } from "react";
import { CodeBlock } from "./code-block";

let mermaidLoader = null;

function loadMermaid() {
  if (typeof window === "undefined") {
    return Promise.resolve(null);
  }

  if (window.mermaid) {
    return Promise.resolve(window.mermaid);
  }

  if (!mermaidLoader) {
    mermaidLoader = new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = "https://unpkg.com/mermaid@10/dist/mermaid.min.js";
      script.async = true;
      script.onload = () => resolve(window.mermaid);
      script.onerror = reject;
      document.head.appendChild(script);
    });
  }

  return mermaidLoader;
}

export function MermaidBlock({ chart }) {
  const chartId = useId().replace(/:/g, "");
  const [svg, setSvg] = useState("");

  useEffect(() => {
    let cancelled = false;

    loadMermaid()
      .then(async (mermaid) => {
        if (!mermaid) {
          return;
        }

        mermaid.initialize({
          startOnLoad: false,
          securityLevel: "loose",
          theme: "neutral",
          fontFamily: '"IBM Plex Sans", "Helvetica Neue", Arial, sans-serif',
          flowchart: {
            htmlLabels: false,
            useMaxWidth: true,
            nodeSpacing: 38,
            rankSpacing: 48,
          },
        });

        const rendered = await mermaid.render(`raylimit-${chartId}`, chart);

        if (!cancelled) {
          setSvg(rendered.svg);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSvg("");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [chart, chartId]);

  if (!svg) {
    return <CodeBlock value={chart} />;
  }

  return (
    <div className="mermaid-frame">
      <div className="mermaid-canvas" dangerouslySetInnerHTML={{ __html: svg }} />
    </div>
  );
}
