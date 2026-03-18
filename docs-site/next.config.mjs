const isProduction = process.env.NODE_ENV === "production";
const basePath = isProduction ? "/RayLimit" : "";

const nextConfig = {
  output: "export",
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  basePath,
  assetPrefix: basePath,
};

export default nextConfig;
