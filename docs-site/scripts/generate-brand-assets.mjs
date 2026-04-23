import brandAssets from '../brand-assets.json' with { type: 'json' };
import { copyFile, mkdir, readdir, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import sharp from 'sharp';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const docsSiteDir = path.resolve(scriptDir, '..');
const repoRoot = path.resolve(docsSiteDir, '..');
const sourceDir = path.join(repoRoot, 'assets', 'logo');
const publicDir = path.join(docsSiteDir, 'public');
const brandAssetNamespace = brandAssets.namespace;
const brandAssetFiles = brandAssets.files;
const brandPublicDir = path.join(publicDir, ...brandAssetNamespace.split('/'));
const brandNamespaceRootDir = path.join(publicDir, 'brand');
const currentBrandSlug = path.basename(brandPublicDir);

const brandIconVariants = {
  dark: {
    background: '#000000',
    pngOutput: path.join(sourceDir, 'raylimit-icon-white.png'),
    svgPublicCopy: path.join(brandPublicDir, brandAssetFiles.icons.dark),
    svgSource: path.join(sourceDir, 'raylimit-icon-white.svg'),
  },
  light: {
    background: '#ffffff',
    pngOutput: path.join(sourceDir, 'raylimit-icon.png'),
    svgPublicCopy: path.join(brandPublicDir, brandAssetFiles.icons.light),
    svgSource: path.join(sourceDir, 'raylimit-icon.svg'),
  },
};
const sitePngOutputs = {
  appleTouchIcon: path.join(brandPublicDir, brandAssetFiles.appleTouchIcon),
  favicon: path.join(brandPublicDir, brandAssetFiles.favicon),
  manifest: path.join(brandPublicDir, brandAssetFiles.manifest),
  manifestIcons: {
    large: path.join(brandPublicDir, brandAssetFiles.manifestIcons.large),
    small: path.join(brandPublicDir, brandAssetFiles.manifestIcons.small),
  },
  socialPreview: path.join(brandPublicDir, brandAssetFiles.previewImage),
};
const legacyPublicFiles = [
  'apple-touch-icon.png',
  'icon-192.png',
  'icon-512.png',
  'manifest.json',
  'og-preview.png',
  'raylimit-icon-white.svg',
  'raylimit-icon.svg',
];

const iconCanvasSize = 512;
const iconContentSize = 408;
const iconCornerRadius = 96;
const ogWidth = 1200;
const ogHeight = 630;

function roundedMask(size, radius) {
  return Buffer.from(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      <rect width="${size}" height="${size}" rx="${radius}" ry="${radius}" fill="#ffffff" />
    </svg>`,
  );
}

async function ensureDirectories() {
  await mkdir(sourceDir, { recursive: true });
  await mkdir(publicDir, { recursive: true });
  await mkdir(brandPublicDir, { recursive: true });
}

async function removeObsoletePublicAssets() {
  const generatedPrefixes = [
    'apple-touch-icon-',
    'icon-192-',
    'icon-512-',
    'manifest-',
    'og-preview-',
    'raylimit-favicon-',
    'raylimit-icon-',
    'raylimit-icon-white-',
  ];
  const publicEntries = await readdir(publicDir, { withFileTypes: true });

  await Promise.all(
    publicEntries.flatMap((entry) => {
      if (!entry.isFile()) {
        return [];
      }

      const filePath = path.join(publicDir, entry.name);
      const isLegacyFile = legacyPublicFiles.includes(entry.name);
      const isVersionedGeneratedFile = generatedPrefixes.some((prefix) =>
        entry.name.startsWith(prefix),
      );

      if (isLegacyFile || isVersionedGeneratedFile) {
        return unlink(filePath);
      }

      return [];
    }),
  );

  const brandEntries = await readdir(brandNamespaceRootDir, { withFileTypes: true });

  await Promise.all(
    brandEntries.flatMap((entry) => {
      if (entry.name === currentBrandSlug) {
        return [];
      }

      return rm(path.join(brandNamespaceRootDir, entry.name), {
        force: true,
        recursive: true,
      });
    }),
  );
}

async function syncSvgCopies() {
  for (const asset of Object.values(brandIconVariants)) {
    await copyFile(asset.svgSource, asset.svgPublicCopy);
  }
}

async function renderTrimmedSvg(svgPath) {
  return sharp(svgPath, { density: 384 }).ensureAlpha().trim().png().toBuffer();
}

async function renderBrandedIcon({ background, outputPath, svgPath, size = iconCanvasSize }) {
  const icon = await sharp(await renderTrimmedSvg(svgPath))
    .resize({
      background: { alpha: 0, b: 0, g: 0, r: 0 },
      fit: 'contain',
      height: Math.round((iconContentSize / iconCanvasSize) * size),
      kernel: sharp.kernel.lanczos3,
      width: Math.round((iconContentSize / iconCanvasSize) * size),
    })
    .png()
    .toBuffer();

  await sharp({
    create: {
      background,
      channels: 4,
      height: size,
      width: size,
    },
  })
    .composite([
      { gravity: 'center', input: icon },
      {
        blend: 'dest-in',
        input: roundedMask(size, Math.round((iconCornerRadius / iconCanvasSize) * size)),
      },
    ])
    .png()
    .toFile(outputPath);
}

function svgDataUri(source) {
  return `data:image/svg+xml;base64,${Buffer.from(source).toString('base64')}`;
}

function faviconSvg() {
  return Buffer.from(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 1000">
      <style>
        :root { --icon-color: #000000; }
        @media (prefers-color-scheme: dark) {
          :root { --icon-color: #ffffff; }
        }
        .brand-fill { fill: var(--icon-color); }
        .brand-stroke {
          fill: none;
          stroke: var(--icon-color);
          stroke-linecap: round;
          stroke-linejoin: round;
          stroke-width: 54;
        }
      </style>
      <g class="brand-fill" transform="translate(280 120) scale(0.72)">
        <polygon points="530,530 900,530 650,650 530,1000" />
        <polygon points="470,530 470,900 350,650 0,530" />
        <polygon points="530,470 530,100 650,350 1000,470" />
        <polygon points="470,470 100,470 350,350 470,0" />
      </g>
      <g class="brand-stroke">
        <path d="M248 88C184 88 160 126 160 202V324C160 395 126 443 84 470C126 497 160 545 160 616V798C160 874 184 912 248 912" />
        <path d="M1032 88C1096 88 1120 126 1120 202V324C1120 395 1154 443 1196 470C1154 497 1120 545 1120 616V798C1120 874 1096 912 1032 912" />
      </g>
    </svg>`,
  );
}

function ogPreviewSvg(iconSource) {
  const iconUri = svgDataUri(iconSource);

  return Buffer.from(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${ogWidth}" height="${ogHeight}" viewBox="0 0 ${ogWidth} ${ogHeight}">
      <rect width="${ogWidth}" height="${ogHeight}" fill="#f4f7fa" />
      <rect x="54" y="54" width="1092" height="522" rx="36" fill="#ffffff" stroke="#d7dee7" stroke-width="2" />
      <rect x="110" y="108" width="132" height="132" rx="30" fill="#ffffff" stroke="#d7dee7" stroke-width="2" />
      <image href="${iconUri}" x="122" y="120" width="108" height="108" preserveAspectRatio="xMidYMid meet" />
      <text x="276" y="156" fill="#0a0d12" font-family="Arial, Helvetica, sans-serif" font-size="72" font-weight="700">RayLimit</text>
      <text x="276" y="206" fill="#5d6672" font-family="Arial, Helvetica, sans-serif" font-size="28" font-weight="500">Documentation</text>
      <text x="110" y="322" fill="#0a0d12" font-family="Arial, Helvetica, sans-serif" font-size="48" font-weight="600">Operator-grade traffic shaping for Xray</text>
      <text x="110" y="382" fill="#0a0d12" font-family="Arial, Helvetica, sans-serif" font-size="48" font-weight="600">runtimes on Linux.</text>
      <text x="110" y="452" fill="#5d6672" font-family="Arial, Helvetica, sans-serif" font-size="28" font-weight="400">Discover runtimes, inspect the live target, and apply guarded IP,</text>
      <text x="110" y="490" fill="#5d6672" font-family="Arial, Helvetica, sans-serif" font-size="28" font-weight="400">inbound, and outbound speed limiters with dry-run-first workflows.</text>
      <text x="110" y="535" fill="#3f4752" font-family="Arial, Helvetica, sans-serif" font-size="24" font-weight="500">Getting Started · Commands · Limiters · Reference</text>
      <text x="1100" y="535" fill="#5d6672" font-family="Arial, Helvetica, sans-serif" font-size="24" font-weight="500" text-anchor="end">pdyrust.github.io/RayLimit</text>
    </svg>`,
  );
}

async function buildOgPreview() {
  const iconSource = await readFile(brandIconVariants.light.svgSource, 'utf8');

  await sharp(ogPreviewSvg(iconSource)).png().toFile(sitePngOutputs.socialPreview);
}

async function buildSiteIcons() {
  await sharp(brandIconVariants.light.pngOutput)
    .resize(180, 180, { fit: 'cover', kernel: sharp.kernel.lanczos3 })
    .png()
    .toFile(sitePngOutputs.appleTouchIcon);

  await sharp(brandIconVariants.light.pngOutput)
    .resize(192, 192, { fit: 'cover', kernel: sharp.kernel.lanczos3 })
    .png()
    .toFile(sitePngOutputs.manifestIcons.small);

  await sharp(brandIconVariants.light.pngOutput)
    .resize(512, 512, { fit: 'cover', kernel: sharp.kernel.lanczos3 })
    .png()
    .toFile(sitePngOutputs.manifestIcons.large);
}

async function buildFavicon() {
  await writeFile(sitePngOutputs.favicon, faviconSvg());
}

async function buildManifest() {
  const manifest = {
    name: 'RayLimit Documentation',
    short_name: 'RayLimit Docs',
    theme_color: '#ffffff',
    background_color: '#ffffff',
    display: 'standalone',
    scope: '.',
    start_url: '.',
    icons: [
      {
        src: brandAssetFiles.manifestIcons.small,
        type: 'image/png',
        sizes: '192x192',
      },
      {
        src: brandAssetFiles.manifestIcons.large,
        type: 'image/png',
        sizes: '512x512',
      },
    ],
  };

  await writeFile(sitePngOutputs.manifest, `${JSON.stringify(manifest, null, 2)}\n`);
}

async function main() {
  await ensureDirectories();
  await removeObsoletePublicAssets();
  await syncSvgCopies();

  await renderBrandedIcon({
    background: brandIconVariants.light.background,
    outputPath: brandIconVariants.light.pngOutput,
    svgPath: brandIconVariants.light.svgSource,
  });

  await renderBrandedIcon({
    background: brandIconVariants.dark.background,
    outputPath: brandIconVariants.dark.pngOutput,
    svgPath: brandIconVariants.dark.svgSource,
  });

  await buildSiteIcons();
  await buildFavicon();
  await buildManifest();
  await buildOgPreview();
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
