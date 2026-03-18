import Link from "next/link";
import { MarkdownContent } from "../components/markdown-content";
import { SiteFooter } from "../components/site-footer";
import { SiteHeader } from "../components/site-header";
import { withBasePath } from "../lib/base-path";
import { getNavigationGroups, getRootDocument, siteMeta } from "../lib/docs";

const limiterCards = [
  {
    title: "IP",
    body: "Direct client-IP shaping, including the current native IPv6 scope.",
  },
  {
    title: "UUID",
    body: "Shared-pool identity shaping in the current exact-user-safe scopes.",
  },
  {
    title: "Inbound and outbound",
    body: "Concrete in their selector-qualified host-visible scopes.",
  },
  {
    title: "Connection",
    body: "Foundational work is in place, with broader development planned for future releases.",
  },
];

export default function HomePage() {
  const doc = getRootDocument();
  const navGroups = getNavigationGroups();
  const repositoryLabel = siteMeta.repository.replace("https://github.com/", "");
  const repoBrand = (
    <div className="hero-panel-brand">
      <img
        src={withBasePath("/raylimit-icon.svg")}
        alt="RayLimit icon"
        width="30"
        height="30"
      />
      <span className="hero-panel-repo">{repositoryLabel}</span>
    </div>
  );

  return (
    <div className="site-frame">
      <SiteHeader currentHref="/" currentTitle={doc.title} navGroups={navGroups} />
      <main className="landing-shell" lang="en" dir="ltr">
        <section className="hero-panel">
          <div className="hero-copy">
            <div className="hero-panel-brand-mobile">{repoBrand}</div>
            <div className="hero-badges">
              <span className="badge badge-muted">{siteMeta.version}</span>
              <span className="badge badge-muted">Linux docs</span>
            </div>
            <h1>{siteMeta.tagline}</h1>
            <p className="hero-lead">
              RayLimit is a Linux CLI for discovering Xray runtimes, inspecting
              runtime state, and applying guarded speed limiters with dry-run-first
              workflows.
            </p>
            <div className="hero-actions">
              <Link className="button button-primary" href="/docs">
                Open docs
              </Link>
              <Link className="button" href="/docs/getting-started/installation">
                Start with installation
              </Link>
            </div>
          </div>
          <div className="hero-panel-card">
            <div className="hero-panel-brand-desktop">{repoBrand}</div>
            <div className="callout-grid">
              <div className="callout-card">
                <h2>Release install</h2>
                <p>Use the packaged install path when you want a normal host deployment.</p>
              </div>
              <div className="callout-card">
                <h2>Run from source</h2>
                <p>Use `go run` or `make build` when you are validating or developing locally.</p>
              </div>
            </div>
          </div>
        </section>

        <section className="card-grid">
          {limiterCards.map((item) => (
            <article key={item.title} className="feature-card">
              <h2>{item.title}</h2>
              <p>{item.body}</p>
            </article>
          ))}
        </section>

        <section className="landing-doc-panel">
          <div className="landing-doc-header">
            <span className="eyebrow">Documentation overview</span>
            <h2>{doc.title}</h2>
            {doc.lead ? <p>{doc.lead}</p> : null}
          </div>
          <MarkdownContent doc={doc} />
        </section>
      </main>
      <SiteFooter />
    </div>
  );
}
