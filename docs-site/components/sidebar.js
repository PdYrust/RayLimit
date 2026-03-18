import Link from "next/link";

export function Sidebar({ navGroups, currentHref }) {
  return (
    <nav className="sidebar-nav" aria-label="Documentation sections">
      {navGroups.map((group) => (
        <section key={group.title} className="sidebar-group">
          <h2>{group.title}</h2>
          <ul>
            {group.items.map((item) => {
              const active = item.href === currentHref;

              return (
                <li key={item.href}>
                  <Link
                    className={active ? "sidebar-link active" : "sidebar-link"}
                    aria-current={active ? "page" : undefined}
                    href={item.href}
                  >
                    {item.title}
                  </Link>
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </nav>
  );
}
