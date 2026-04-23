import { DocsThemeConfig, useConfig } from 'nextra-theme-docs';
import { useRouter } from 'next/router';
import { useTheme } from 'next-themes';
import { useEffect, useState } from 'react';

import brandAssets from './brand-assets.json';

const SITE_TITLE = 'RayLimit Documentation';
const SITE_DESCRIPTION = 'Operator-grade traffic shaping documentation for Xray runtimes on Linux.';
const SITE_URL = 'https://pdyrust.github.io/RayLimit';
const REPOSITORY_URL = 'https://github.com/PdYrust/RayLimit';
const TELEGRAM_URL = 'https://t.me/PdYrust';
const SOCIAL_PREVIEW_ALT = 'RayLimit documentation preview';
const SOCIAL_PREVIEW_HEIGHT = 630;
const SOCIAL_PREVIEW_TYPE = 'image/png';
const SOCIAL_PREVIEW_WIDTH = 1200;
const BRAND_SURFACES = {
  dark: '#000000',
  light: '#ffffff',
} as const;
const BRAND_ASSET_NAMESPACE = brandAssets.namespace;
const BRAND_ASSET_FILES = brandAssets.files;
const SOCIAL_PREVIEW_IMAGE = `${SITE_URL}/${BRAND_ASSET_NAMESPACE}/${BRAND_ASSET_FILES.previewImage}`;

function assetPath(basePath: string, fileName: string): string {
  return `${basePath || ''}/${BRAND_ASSET_NAMESPACE}/${fileName}`;
}

function brandAssetPaths(basePath: string) {
  return {
    appleTouchIcon: assetPath(basePath, BRAND_ASSET_FILES.appleTouchIcon),
    favicon: assetPath(basePath, BRAND_ASSET_FILES.favicon),
    icons: {
      dark: assetPath(basePath, BRAND_ASSET_FILES.icons.dark),
      light: assetPath(basePath, BRAND_ASSET_FILES.icons.light),
    },
    manifest: assetPath(basePath, BRAND_ASSET_FILES.manifest),
  };
}

function BrandLogoMark() {
  const { basePath = '' } = useRouter();
  const { resolvedTheme } = useTheme();
  const [isThemeReady, setIsThemeReady] = useState(false);
  const assetPaths = brandAssetPaths(basePath);
  const isDarkTheme = isThemeReady && resolvedTheme === 'dark';

  useEffect(() => {
    setIsThemeReady(true);
  }, []);

  return (
    <div aria-hidden="true" className="nx-relative nx-h-10 nx-w-10 nx-shrink-0">
      <img
        alt=""
        className="nx-absolute nx-inset-0 nx-block nx-h-10 nx-w-10 dark:nx-hidden"
        height="40"
        src={assetPaths.icons.light}
        style={{
          display: isThemeReady ? (isDarkTheme ? 'none' : 'block') : undefined,
        }}
        width="40"
      />
      <img
        alt=""
        className="nx-absolute nx-inset-0 nx-hidden nx-h-10 nx-w-10 dark:nx-block"
        height="40"
        src={assetPaths.icons.dark}
        style={{
          display: isThemeReady ? (isDarkTheme ? 'block' : 'none') : undefined,
        }}
        width="40"
      />
    </div>
  );
}

function BrandLogo() {
  return (
    <div className="nx-flex nx-items-center nx-gap-4">
      <BrandLogoMark />
      <div className="nx-flex nx-flex-col nx-gap-0.5">
        <span className="nx-font-bold nx-leading-none max-[500px]:text-lg min-[500px]:text-xl">
          RayLimit
        </span>
        <span className="nx-text-xs nx-leading-4 nx-text-gray-500 dark:nx-text-gray-400">
          Documentation
        </span>
      </div>
    </div>
  );
}

function TelegramIcon() {
  return (
    <svg fill="none" height="18" viewBox="0 0 24 24" width="18" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M21.5 4.5L18.1 20.4C17.8 21.5 17 21.8 16 21.3L10.9 17.6L8.4 20C8.1 20.3 7.9 20.5 7.4 20.5L7.8 15.2L17.5 6.5C17.9 6.1 17.4 5.9 16.8 6.3L4.8 13.8L0 12.3C-1 12 -1 11.3 0.2 10.8L19 3.6C19.9 3.3 20.7 3.8 21.5 4.5Z"
        fill="currentColor"
      />
    </svg>
  );
}

const config: DocsThemeConfig = {
  logo: <BrandLogo />,
  darkMode: true,
  nextThemes: {
    defaultTheme: 'system',
  },
  project: {
    link: REPOSITORY_URL,
  },
  chat: {
    icon: <TelegramIcon />,
    link: TELEGRAM_URL,
  },
  docsRepositoryBase: `${REPOSITORY_URL}/tree/main/docs-site`,
  editLink: {
    text: 'Edit this page on GitHub →',
  },
  feedback: {
    useLink: () => `${REPOSITORY_URL}/issues/new`,
  },
  useNextSeoProps: () => ({
    titleTemplate: '%s',
    description: SITE_DESCRIPTION,
    openGraph: {
      type: 'website',
      locale: 'en_US',
      siteName: 'RayLimit Documentation',
      description: SITE_DESCRIPTION,
    },
  }),
  toc: {
    float: true,
  },
  footer: {
    text: <span>RayLimit documentation by YrustPd.</span>,
  },
  head: () => {
    const { title } = useConfig();
    const { asPath, basePath = '', route } = useRouter();
    const currentPath = (asPath || '/').split('#')[0].split('?')[0];
    const canonicalPath = currentPath === '/' ? '' : currentPath;
    const canonicalUrl = `${SITE_URL}${canonicalPath}`;
    const pageTitle = title && route !== '/' ? `${title} – RayLimit Documentation` : SITE_TITLE;
    const assetPaths = brandAssetPaths(basePath);

    return (
      <>
        <meta
          content="raylimit, xray, linux, tc, nftables, traffic shaping, documentation"
          name="keywords"
        />
        <meta content="light dark" name="color-scheme" />
        <meta
          content={BRAND_SURFACES.light}
          media="(prefers-color-scheme: light)"
          name="theme-color"
        />
        <meta
          content={BRAND_SURFACES.dark}
          media="(prefers-color-scheme: dark)"
          name="theme-color"
        />
        <link href={canonicalUrl} rel="canonical" />
        <meta content={canonicalUrl} property="og:url" />
        <meta content={SOCIAL_PREVIEW_IMAGE} property="og:image" />
        <meta content={SOCIAL_PREVIEW_TYPE} property="og:image:type" />
        <meta content={`${SOCIAL_PREVIEW_WIDTH}`} property="og:image:width" />
        <meta content={`${SOCIAL_PREVIEW_HEIGHT}`} property="og:image:height" />
        <meta content="summary_large_image" name="twitter:card" />
        <meta content={pageTitle} name="twitter:title" />
        <meta content={SOCIAL_PREVIEW_IMAGE} name="twitter:image" />
        <meta content={SOCIAL_PREVIEW_ALT} name="twitter:image:alt" />
        <meta content="RayLimit" name="apple-mobile-web-app-title" />
        <link href={assetPaths.favicon} rel="icon" sizes="64x64" type="image/png" />
        <link href={assetPaths.appleTouchIcon} rel="apple-touch-icon" />
        <link href={assetPaths.manifest} rel="manifest" />
      </>
    );
  },
};

export default config;
