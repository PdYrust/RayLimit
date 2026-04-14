const withNextra = require('nextra')({
  theme: 'nextra-theme-docs',
  themeConfig: './theme.config.tsx',
});

const isGhPages = process.env.GHPAGES === '1';
const repoName = 'RayLimit';

module.exports = withNextra({
  images: {
    unoptimized: true,
  },
  experimental: {
    largePageDataBytes: 161 * 1000,
  },
  reactStrictMode: true,
  ...(isGhPages && {
    basePath: `/${repoName}`,
    assetPrefix: `/${repoName}/`,
    trailingSlash: true,
  }),
});
