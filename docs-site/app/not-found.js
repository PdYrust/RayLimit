import Link from "next/link";
import { SiteFooter } from "../components/site-footer";
import { SiteHeader } from "../components/site-header";
import { getNavigationGroups } from "../lib/docs";

export default function NotFound() {
  const navGroups = getNavigationGroups();

  return (
    <div className="site-frame">
      <SiteHeader currentHref="" currentTitle="Not found" navGroups={navGroups} />
      <main className="not-found-shell">
        <div className="not-found-card">
          <span className="eyebrow">Not found</span>
          <h1>This documentation page does not exist.</h1>
          <p>
            Continue from the RayLimit documentation overview or return to the
            site home page.
          </p>
          <div className="hero-actions">
            <Link className="button button-primary" href="/docs">
              Open docs
            </Link>
            <Link className="button" href="/">
              Go home
            </Link>
          </div>
        </div>
      </main>
      <SiteFooter />
    </div>
  );
}
