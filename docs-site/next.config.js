const withNextra = require('nextra')({
  theme: 'nextra-theme-docs',
  themeConfig: './theme.config.tsx',
});

const isGhPages = process.env.GHPAGES === '1';
const repoName = 'RayLimit';
const docsBasePath = isGhPages ? `/${repoName}` : '';

module.exports = withNextra({
  env: {
    NEXT_PUBLIC_DOCS_BASE_PATH: docsBasePath,
  },
  images: {
    unoptimized: true,
  },
  experimental: {
    largePageDataBytes: 161 * 1000,
  },
  reactStrictMode: true,
  ...(isGhPages && {
    basePath: docsBasePath,
    output: 'export',
    assetPrefix: `${docsBasePath}/`,
    trailingSlash: true,
  }),
});
