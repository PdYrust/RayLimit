import { notFound } from "next/navigation";
import { DocsLayout } from "../../../components/docs-layout";
import { getAllDocParams, getDocByRoute, siteMeta } from "../../../lib/docs";

export function generateStaticParams() {
  return getAllDocParams();
}

export async function generateMetadata({ params }) {
  const { slug = [] } = await params;
  const doc = getDocByRoute(slug);

  if (!doc) {
    return {};
  }

  return {
    title: doc.title,
    description: doc.lead || siteMeta.tagline,
  };
}

export default async function DocsPage({ params }) {
  const { slug = [] } = await params;
  const doc = getDocByRoute(slug);

  if (!doc) {
    notFound();
  }

  return <DocsLayout doc={doc} />;
}
