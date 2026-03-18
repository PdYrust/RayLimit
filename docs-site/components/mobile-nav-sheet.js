"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { withBasePath } from "../lib/base-path";
import { MenuIcon } from "./ui-icons";

function isCurrentPage(currentHref, href) {
  return currentHref === href;
}

export function MobileNavSheet({
  currentHref,
  currentTitle,
  navGroups,
}) {
  const [status, setStatus] = useState("closed");
  const overviewGroup = navGroups.find((group) => group.title === "Overview");
  const overviewItem = overviewGroup?.items[0];
  const visibleGroups = navGroups.filter((group) => group.title !== "Overview");
  const displayTitle =
    currentHref === "/" || currentHref === "/docs" ? "Browse docs" : currentTitle;
  const isMounted = status !== "closed";
  const isOpen = status === "open";
  const ui = {
    trigger: "Menu",
    title: "Documentation",
    home: "Home",
    overview: "Docs overview",
  };

  useEffect(() => {
    if (status === "closed" || typeof document === "undefined") {
      return undefined;
    }

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    function handleKeyDown(event) {
      if (event.key === "Escape") {
        setStatus((current) => (current === "closed" ? current : "closing"));
      }
    }

    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [status]);

  useEffect(() => {
    if (status !== "opening" || typeof window === "undefined") {
      return undefined;
    }

    const frame = window.requestAnimationFrame(() => {
      setStatus("open");
    });

    return () => window.cancelAnimationFrame(frame);
  }, [status]);

  useEffect(() => {
    if (status !== "closing" || typeof window === "undefined") {
      return undefined;
    }

    const timeout = window.setTimeout(() => {
      setStatus("closed");
    }, 220);

    return () => window.clearTimeout(timeout);
  }, [status]);

  function openSheet() {
    setStatus("opening");
  }

  function closeSheet() {
    setStatus((current) => (current === "closed" ? current : "closing"));
  }

  return (
    <>
      <button type="button" className="mobile-menu-trigger" onClick={openSheet}>
        <MenuIcon />
        <span>{ui.trigger}</span>
      </button>
      {isMounted ? (
        <div
          className={isOpen ? "mobile-sheet-root is-open" : "mobile-sheet-root is-closing"}
          dir="ltr"
        >
          <button
            type="button"
            className="mobile-sheet-backdrop"
            aria-label="Close navigation"
            onClick={closeSheet}
          />
          <section className="mobile-sheet" lang="en">
            <div className="mobile-sheet-topbar">
              <div className="mobile-sheet-intro">
                <div className="mobile-sheet-brand-row">
                  <img
                    className="mobile-sheet-brand-icon"
                    src={withBasePath("/raylimit-icon.svg")}
                    alt="RayLimit icon"
                    width="24"
                    height="24"
                  />
                  <div className="mobile-sheet-brand-copy">
                    <span className="mobile-sheet-kicker">{ui.title}</span>
                    <p className="mobile-sheet-current">{displayTitle}</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="mobile-sheet-scroll">
              <div className="mobile-sheet-actions">
                {overviewItem ? (
                  <Link
                    className={
                      isCurrentPage(currentHref, overviewItem.href)
                        ? "mobile-sheet-shortcut active"
                        : "mobile-sheet-shortcut"
                    }
                    href={overviewItem.href}
                    onClick={closeSheet}
                  >
                    {ui.overview}
                  </Link>
                ) : null}
                <Link className="mobile-home-link" href="/" onClick={closeSheet}>
                  <span>{ui.home}</span>
                </Link>
              </div>

              <nav className="mobile-sheet-groups" aria-label="Documentation sections">
                {visibleGroups.map((group) => (
                  <section
                    key={group.title}
                    className={
                      group.items.some((item) => item.href === currentHref)
                        ? "mobile-sheet-group active"
                        : "mobile-sheet-group"
                    }
                  >
                    <div className="mobile-sheet-group-head">
                      <h3>{group.title}</h3>
                    </div>
                    <div className="mobile-sheet-links">
                      {group.items.map((item) => (
                        <Link
                          key={item.href}
                          className={
                            isCurrentPage(currentHref, item.href)
                              ? "mobile-sheet-link active"
                              : "mobile-sheet-link"
                          }
                          aria-current={isCurrentPage(currentHref, item.href) ? "page" : undefined}
                          href={item.href}
                          onClick={closeSheet}
                        >
                          <span>{item.title}</span>
                        </Link>
                      ))}
                    </div>
                  </section>
                ))}
              </nav>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}
