import { MarkdownContent } from "./markdown-content";
import { SiteFooter } from "./site-footer";
import { Sidebar } from "./sidebar";
import { SiteHeader } from "./site-header";
import { Toc } from "./toc";
import { getNavigationGroups } from "../lib/docs";

export function DocsLayout({ doc }) {
  const navGroups = getNavigationGroups();

  return (
    <div className="site-frame">
      <SiteHeader
        currentHref={doc.href}
        currentTitle={doc.title}
        currentSection={doc.sectionLabel}
        navGroups={navGroups}
      />
      <main className="docs-shell" dir="ltr" lang="en">
        <aside className="docs-sidebar">
          <Sidebar navGroups={navGroups} currentHref={doc.href} />
        </aside>
        <section className="docs-main">
          <div className="docs-main-header">
            <span className="eyebrow">{doc.sectionLabel}</span>
            <h1>{doc.title}</h1>
            {doc.lead ? <p className="docs-lead">{doc.lead}</p> : null}
          </div>
          <MarkdownContent doc={doc} />
        </section>
        <aside className="docs-toc">
          <Toc headings={doc.headings} />
        </aside>
      </main>
      <SiteFooter />
    </div>
  );
}
