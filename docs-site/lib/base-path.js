const productionBasePath = "/RayLimit";

export const basePath = process.env.NODE_ENV === "production" ? productionBasePath : "";

export function withBasePath(value) {
  if (!basePath) {
    return value;
  }

  if (!value || value === "/") {
    return `${basePath}/`;
  }

  return `${basePath}${value}`;
}
