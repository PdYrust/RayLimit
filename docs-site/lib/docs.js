import fs from "fs";
import path from "path";

const repositoryRoot = path.join(process.cwd(), "..");
const docsRoot = path.join(repositoryRoot, "docs");
const rawVersion = fs.readFileSync(path.join(repositoryRoot, "VERSION"), "utf8").trim();

export const siteMeta = {
  title: "RayLimit",
  version: `v${rawVersion}`,
  tagline: "Reconcile-aware traffic shaping for Xray runtimes on Linux.",
  repository: "https://github.com/PdYrust/RayLimit",
  telegram: "https://t.me/PdYrust",
};

const navigation = [
  {
    title: "Overview",
    items: [{ title: "Documentation", slug: [], file: "en/index.md" }],
  },
  {
    title: "Getting started",
    items: [
      { title: "Installation", slug: ["getting-started", "installation"], file: "en/getting-started/installation.md" },
      { title: "Common commands", slug: ["getting-started", "common-commands"], file: "en/getting-started/common-commands.md" },
      { title: "Practical usage", slug: ["getting-started", "practical-usage"], file: "en/getting-started/practical-usage.md" },
    ],
  },
  {
    title: "Speed limiters",
    items: [
      { title: "Overview", slug: ["speed-limiters"], file: "en/speed-limiters/index.md" },
      { title: "IP", slug: ["speed-limiters", "ip"], file: "en/speed-limiters/ip.md" },
      { title: "UUID", slug: ["speed-limiters", "uuid"], file: "en/speed-limiters/uuid.md" },
      { title: "Inbound", slug: ["speed-limiters", "inbound"], file: "en/speed-limiters/inbound.md" },
      { title: "Outbound", slug: ["speed-limiters", "outbound"], file: "en/speed-limiters/outbound.md" },
      { title: "Connection", slug: ["speed-limiters", "connection"], file: "en/speed-limiters/connection.md" },
    ],
  },
  {
    title: "Reference",
    items: [
      { title: "Validation", slug: ["reference", "validation"], file: "en/reference/validation.md" },
      { title: "Troubleshooting", slug: ["reference", "troubleshooting"], file: "en/reference/troubleshooting.md" },
      { title: "Glossary", slug: ["reference", "glossary"], file: "en/reference/glossary.md" },
    ],
  },
  {
    title: "Internals",
    items: [
      { title: "Architecture", slug: ["internals", "architecture"], file: "en/internals/architecture.md" },
      { title: "Development", slug: ["internals", "development"], file: "en/internals/development.md" },
    ],
  },
  {
    title: "Diagrams",
    items: [{ title: "Visual explanations", slug: ["diagrams"], file: "en/diagrams/index.md" }],
  },
];

function normalizeSlug(slug = []) {
  return slug.filter(Boolean);
}

function flattenNavigation() {
  return navigation.flatMap((group) =>
    group.items.map((item) => ({
      ...item,
      href: buildDocHref(item.slug),
      groupTitle: group.title,
    }))
  );
}

function parseMarkdownDocument(source) {
  const normalized = source.replace(/\r\n/g, "\n").trim();
  const titleMatch = normalized.match(/^#\s+(.+)$/m);
  const title = titleMatch ? titleMatch[1].trim() : siteMeta.title;
  const bodyWithoutTitle = normalized.replace(/^#\s+.+\n+/, "");
  const blocks = bodyWithoutTitle.split(/\n{2,}/);
  const firstBlock = blocks[0] || "";
  const looksLikeLead =
    firstBlock &&
    !firstBlock.startsWith("##") &&
    !firstBlock.startsWith("```") &&
    !firstBlock.startsWith("- ") &&
    !firstBlock.startsWith("1.") &&
    !firstBlock.startsWith("|");
  const lead = looksLikeLead ? firstBlock.replace(/\n/g, " ").trim() : "";
  const body = looksLikeLead ? bodyWithoutTitle.slice(firstBlock.length).trimStart() : bodyWithoutTitle;
  const headings = [...body.matchAll(/^(##|###)\s+(.+)$/gm)].map((match) => ({
    level: match[1].length,
    text: match[2].trim(),
    id: slugifyText(match[2].trim()),
  }));

  return {
    title,
    lead,
    body,
    headings,
  };
}

function readDocument(file) {
  return fs.readFileSync(path.join(docsRoot, file), "utf8");
}

function buildDocHref(slug = []) {
  const parts = normalizeSlug(slug);
  return parts.length ? `/docs/${parts.join("/")}` : "/docs";
}

function getSourceDirectory(sourceFile) {
  const withoutPrefix = sourceFile.startsWith("en/") ? sourceFile.slice(3) : sourceFile;
  const segments = withoutPrefix.split("/");
  segments.pop();
  return segments;
}

export function slugifyText(value) {
  return value
    .toLowerCase()
    .replace(/[`*_~]/g, "")
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .trim()
    .replace(/\s+/g, "-");
}

export function getNavigationGroups() {
  return navigation.map((group) => ({
    title: group.title,
    items: group.items.map((item) => ({
      title: item.title,
      href: buildDocHref(item.slug),
    })),
  }));
}

export function getAllDocParams() {
  return flattenNavigation().map((item) => ({
    slug: item.slug,
  }));
}

export function getDocByRoute(slug = []) {
  const requested = normalizeSlug(slug);
  const docs = flattenNavigation();
  const match = docs.find((item) => item.slug.join("/") === requested.join("/"));

  if (!match) {
    return null;
  }

  const parsed = parseMarkdownDocument(readDocument(match.file));

  return {
    ...parsed,
    lang: "en",
    direction: "ltr",
    slug: requested,
    href: buildDocHref(requested),
    sectionLabel: match.groupTitle,
    sourceFile: match.file,
  };
}

export function getRootDocument() {
  return {
    ...parseMarkdownDocument(readDocument("index.md")),
    lang: "en",
    direction: "ltr",
    slug: [],
    href: "/",
    sectionLabel: "Documentation overview",
    sourceFile: "index.md",
  };
}

export function resolveDocHref(href, doc) {
  if (!href) {
    return "#";
  }

  if (
    href.startsWith("http://") ||
    href.startsWith("https://") ||
    href.startsWith("mailto:") ||
    href.startsWith("#")
  ) {
    return href;
  }

  const [rawPath, hash = ""] = href.split("#");

  if (!rawPath.endsWith(".md")) {
    return href;
  }

  const currentDir = getSourceDirectory(doc.sourceFile);
  const pieces = rawPath.startsWith("/")
    ? rawPath.replace(/^\/+/, "").split("/")
    : [...currentDir, ...rawPath.split("/")];

  const normalized = [];

  for (const piece of pieces) {
    if (!piece || piece === ".") {
      continue;
    }

    if (piece === "..") {
      normalized.pop();
      continue;
    }

    normalized.push(piece);
  }

  const last = normalized[normalized.length - 1];

  if (last === "index.md") {
    normalized.pop();
  } else if (last && last.endsWith(".md")) {
    normalized[normalized.length - 1] = last.replace(/\.md$/, "");
  }

  const nextHref = buildDocHref(normalized);
  return hash ? `${nextHref}#${hash}` : nextHref;
}
