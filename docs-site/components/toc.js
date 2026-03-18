import Link from "next/link";

export function Toc({ headings }) {
  if (!headings.length) {
    return null;
  }

  return (
    <aside className="toc-panel">
      <h2>On this page</h2>
      <ul>
        {headings.map((heading) => (
          <li key={heading.id} className={`toc-level-${heading.level}`}>
            <Link href={`#${heading.id}`}>{heading.text}</Link>
          </li>
        ))}
      </ul>
    </aside>
  );
}
