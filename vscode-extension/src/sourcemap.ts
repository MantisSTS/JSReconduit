import * as fs from "fs";
import * as http from "http";
import * as https from "https";
import * as path from "path";
import { AssetIndexEntry, SourcemapResult } from "./types";
import { ensureDir, logError } from "./utils";

const INLINE_PREFIX = "data:application/json;base64,";

export function extractSourceMappingUrl(contents: string): string | undefined {
  const marker = "sourceMappingURL=";
  const idx = contents.lastIndexOf(marker);
  if (idx === -1) {
    return undefined;
  }
  let tail = contents.slice(idx + marker.length);
  const newline = tail.search(/[\r\n]/);
  if (newline !== -1) {
    tail = tail.slice(0, newline);
  }
  tail = tail.replace("*/", "").trim();
  return tail || undefined;
}

async function fetchRemote(url: string): Promise<string | null> {
  return new Promise((resolve) => {
    const handler = (res: http.IncomingMessage) => {
      if (!res.statusCode || res.statusCode >= 400) {
        resolve(null);
        return;
      }
      const chunks: Buffer[] = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    };
    const client = url.startsWith("https") ? https : http;
    const req = client.get(url, handler);
    req.on("error", () => resolve(null));
  });
}

function safeFileName(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]+/g, "_");
}

async function writeResolvedSources(
  baseDir: string,
  assetId: string,
  sourcemap: any,
  output: (message: string, error?: unknown) => void
): Promise<string[]> {
  if (!sourcemap || !Array.isArray(sourcemap.sources)) {
    return [];
  }
  const outDir = path.join(baseDir, "resolved", assetId);
  await ensureDir(outDir);
  const resolved: string[] = [];

  for (let i = 0; i < sourcemap.sources.length; i += 1) {
    const source = sourcemap.sources[i];
    const content = sourcemap.sourcesContent ? sourcemap.sourcesContent[i] : undefined;
    if (!content) {
      continue;
    }
    const fileName = safeFileName(source || `source-${i}.js`);
    const filePath = path.join(outDir, fileName);
    try {
      await fs.promises.writeFile(filePath, content, "utf8");
      resolved.push(filePath);
    } catch (error) {
      output("Failed to write resolved source", error);
    }
  }
  return resolved;
}

export async function resolveSourcemap(
  asset: AssetIndexEntry,
  contents: string,
  baseDir: string,
  output: (message: string, error?: unknown) => void
): Promise<SourcemapResult | undefined> {
  const ref = extractSourceMappingUrl(contents) || asset.sourcemap_ref;
  if (!ref) {
    return undefined;
  }

  const sourcemapsDir = path.join(baseDir, "sourcemaps");
  await ensureDir(sourcemapsDir);
  const assetId = asset.sha256.slice(0, 16);
  const sourcemapPath = path.join(sourcemapsDir, `${assetId}.map`);

  let sourcemapRaw: string | null = null;

  if (ref.startsWith(INLINE_PREFIX)) {
    try {
      const encoded = ref.slice(INLINE_PREFIX.length);
      sourcemapRaw = Buffer.from(encoded, "base64").toString("utf8");
    } catch (error) {
      output("Failed to decode inline sourcemap", error);
      return undefined;
    }
  } else if (asset.sourcemap_path && fs.existsSync(asset.sourcemap_path)) {
    sourcemapRaw = await fs.promises.readFile(asset.sourcemap_path, "utf8");
  } else {
    let resolvedUrl = ref;
    try {
      resolvedUrl = new URL(ref, asset.url).toString();
    } catch {
      const localCandidate = path.resolve(path.dirname(asset.raw_path), ref);
      if (fs.existsSync(localCandidate)) {
        sourcemapRaw = await fs.promises.readFile(localCandidate, "utf8");
      }
    }
    if (!sourcemapRaw && (resolvedUrl.startsWith("http://") || resolvedUrl.startsWith("https://"))) {
      sourcemapRaw = await fetchRemote(resolvedUrl);
    }
  }

  if (!sourcemapRaw) {
    return undefined;
  }

  try {
    await fs.promises.writeFile(sourcemapPath, sourcemapRaw, "utf8");
  } catch (error) {
    output("Failed to write sourcemap file", error);
  }

  let parsed: any;
  try {
    parsed = JSON.parse(sourcemapRaw);
  } catch (error) {
    output("Failed to parse sourcemap JSON", error);
    return undefined;
  }

  const resolvedFiles = await writeResolvedSources(baseDir, assetId, parsed, output);
  return {
    sourcemapPath,
    resolvedFiles,
  };
}
