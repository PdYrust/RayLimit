import { DocsThemeConfig, useConfig } from 'nextra-theme-docs';
import { useRouter } from 'next/router';

const SITE_TITLE = 'RayLimit Documentation';
const SITE_DESCRIPTION =
  'Operator-grade traffic shaping documentation for Xray runtimes on Linux.';
const SITE_URL = 'https://pdyrust.github.io/RayLimit';
const REPOSITORY_URL = 'https://github.com/PdYrust/RayLimit';
const TELEGRAM_URL = 'https://t.me/PdYrust';

function assetPath(basePath: string, path: string): string {
  return `${basePath || ''}${path}`;
}

function BrandLogo() {
  const { basePath = '' } = useRouter();
  const lightLogo = assetPath(basePath, '/raylimit-icon.svg');
  const darkLogo = assetPath(basePath, '/raylimit-icon-white.svg');

  return (
    <div className='nx-flex nx-items-center nx-gap-3'>
      <div className='nx-relative nx-h-8 nx-w-8 nx-shrink-0'>
        <img
          alt='RayLimit'
          className='nx-block dark:nx-hidden'
          height='32'
          src={lightLogo}
          width='32'
        />
        <img
          alt='RayLimit'
          className='nx-hidden dark:nx-block'
          height='32'
          src={darkLogo}
          width='32'
        />
      </div>
      <div className='nx-flex nx-flex-col'>
        <span className='nx-font-bold max-[500px]:text-lg min-[500px]:text-xl'>RayLimit</span>
        <span className='nx-text-xs nx-text-gray-500 dark:nx-text-gray-400'>Documentation</span>
      </div>
    </div>
  );
}

function TelegramIcon() {
  return (
    <svg fill='none' height='18' viewBox='0 0 24 24' width='18' xmlns='http://www.w3.org/2000/svg'>
      <path
        d='M21.5 4.5L18.1 20.4C17.8 21.5 17 21.8 16 21.3L10.9 17.6L8.4 20C8.1 20.3 7.9 20.5 7.4 20.5L7.8 15.2L17.5 6.5C17.9 6.1 17.4 5.9 16.8 6.3L4.8 13.8L0 12.3C-1 12 -1 11.3 0.2 10.8L19 3.6C19.9 3.3 20.7 3.8 21.5 4.5Z'
        fill='currentColor'
      />
    </svg>
  );
}

const config: DocsThemeConfig = {
  logo: <BrandLogo />,
  darkMode: true,
  nextThemes: {
    defaultTheme: 'light',
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
      images: [
        {
          url: `${SITE_URL}/og-preview.png`,
        },
      ],
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
    const iconHref = assetPath(basePath, '/raylimit-icon.svg');
    const appleIconHref = assetPath(basePath, '/apple-touch-icon.png');
    const manifestHref = assetPath(basePath, '/manifest.json');
    const ogImage = `${SITE_URL}/og-preview.png`;

    return (
      <>
        <meta
          content='raylimit, xray, linux, tc, nftables, traffic shaping, documentation'
          name='keywords'
        />
        <link href={canonicalUrl} rel='canonical' />
        <meta content={canonicalUrl} property='og:url' />
        <meta content={pageTitle} name='twitter:title' />
        <meta content={ogImage} name='twitter:image' />
        <meta content='RayLimit' name='apple-mobile-web-app-title' />
        <link href={iconHref} rel='icon' type='image/svg+xml' />
        <link href={appleIconHref} rel='apple-touch-icon' />
        <link href={manifestHref} rel='manifest' />
      </>
    );
  },
};

export default config;
