import Link from "next/link";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { CodeBlock } from "./code-block";
import { MermaidBlock } from "./mermaid-block";
import { resolveDocHref, slugifyText } from "../lib/docs";

function flattenNode(children) {
  if (typeof children === "string") {
    return children;
  }

  if (Array.isArray(children)) {
    return children.map(flattenNode).join("");
  }

  if (children && typeof children === "object" && "props" in children) {
    return flattenNode(children.props.children);
  }

  return "";
}

function Heading({ level, children }) {
  const text = flattenNode(children);
  const id = slugifyText(text);

  if (level === 2) {
    return <h2 id={id}>{children}</h2>;
  }

  if (level === 3) {
    return <h3 id={id}>{children}</h3>;
  }

  return <h4 id={id}>{children}</h4>;
}

function inferCodeLanguage(value, className = "") {
  const match = className.match(/language-([\w-]+)/);
  const explicit = match?.[1]?.toLowerCase();

  if (explicit) {
    if (["bash", "sh", "shell", "zsh"].includes(explicit)) {
      return "Bash";
    }

    if (explicit === "js" || explicit === "javascript") {
      return "JavaScript";
    }

    if (explicit === "ts" || explicit === "typescript") {
      return "TypeScript";
    }

    if (explicit === "py" || explicit === "python") {
      return "Python";
    }

    if (explicit === "golang") {
      return "Go";
    }

    if (explicit === "yml") {
      return "YAML";
    }

    return explicit.charAt(0).toUpperCase() + explicit.slice(1);
  }

  const trimmed = value.trim();

  if (!trimmed) {
    return "";
  }

  if (
    /^(sudo\s+)?(\.\/|\/|go run|make\b|tar\b|cd\b|command -v\b|raylimit\b|npm\b|node\b|git\b)/m.test(trimmed)
  ) {
    return "Bash";
  }

  if (/^(package\s+main|func\s+main|import\s+\(|type\s+\w+)/m.test(trimmed)) {
    return "Go";
  }

  if (/^(def\s+\w+|import\s+\w+|from\s+\w+\s+import\s+)/m.test(trimmed)) {
    return "Python";
  }

  if (/^\s*[\[{]/.test(trimmed)) {
    return "JSON";
  }

  return "Text";
}

export function MarkdownContent({ doc }) {
  return (
    <div className="markdown-prose">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h2: ({ children }) => <Heading level={2}>{children}</Heading>,
          h3: ({ children }) => <Heading level={3}>{children}</Heading>,
          h4: ({ children }) => <Heading level={4}>{children}</Heading>,
          a: ({ href = "", children }) => {
            const resolved = resolveDocHref(href, doc);
            const isExternal = resolved.startsWith("http://") || resolved.startsWith("https://");

            if (isExternal) {
              return (
                <a href={resolved} target="_blank" rel="noreferrer">
                  {children}
                </a>
              );
            }

            return <Link href={resolved}>{children}</Link>;
          },
          table: ({ children }) => (
            <div className="table-wrap">
              <table>{children}</table>
            </div>
          ),
          code: ({ className, children }) => {
            const value = String(children).replace(/\n$/, "");

            if (!className) {
              if (!value.includes("\n")) {
                return <code className="inline-code">{value}</code>;
              }

              return <CodeBlock value={value} language={inferCodeLanguage(value)} />;
            }

            if (className.includes("language-mermaid")) {
              return <MermaidBlock chart={value} />;
            }

            return <CodeBlock value={value} language={inferCodeLanguage(value, className)} />;
          },
          pre: ({ children }) => <>{children}</>,
        }}
      >
        {doc.body}
      </ReactMarkdown>
    </div>
  );
}
