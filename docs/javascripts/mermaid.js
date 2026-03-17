const convertMermaidCodeBlocks = () => {
  document.querySelectorAll("pre > code.language-mermaid").forEach((code) => {
    const pre = code.parentElement;
    if (!pre) {
      return;
    }

    const diagram = document.createElement("div");
    diagram.className = "mermaid";
    diagram.textContent = code.textContent || "";
    pre.replaceWith(diagram);
  });
};

const runMermaid = () => {
  convertMermaidCodeBlocks();

  if (typeof window.mermaid === "undefined") {
    return;
  }

  window.mermaid.initialize({
    startOnLoad: false,
    securityLevel: "loose",
    theme: "default",
  });
  window.mermaid.run();
};

if (typeof window.document$ !== "undefined") {
  window.document$.subscribe(runMermaid);
} else {
  runMermaid();
}
