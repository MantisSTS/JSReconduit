import * as fs from "fs";
import * as path from "path";
import { ensureDir } from "./utils";

type DeobfuscatorFn = (input: string) => string;

let cachedDeobfuscator: DeobfuscatorFn | null | undefined;

function loadDeobfuscator(): DeobfuscatorFn | null {
  if (cachedDeobfuscator !== undefined) {
    return cachedDeobfuscator;
  }
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require("javascript-deobfuscator");
    if (typeof mod === "function") {
      cachedDeobfuscator = mod as DeobfuscatorFn;
      return cachedDeobfuscator;
    }
    if (mod && typeof mod.deobfuscate === "function") {
      cachedDeobfuscator = mod.deobfuscate.bind(mod);
      return cachedDeobfuscator;
    }
    if (mod && mod.default) {
      if (typeof mod.default === "function") {
        cachedDeobfuscator = mod.default as DeobfuscatorFn;
        return cachedDeobfuscator;
      }
      if (typeof mod.default.deobfuscate === "function") {
        cachedDeobfuscator = mod.default.deobfuscate.bind(mod.default);
        return cachedDeobfuscator;
      }
    }
  } catch {
    cachedDeobfuscator = null;
    return cachedDeobfuscator;
  }
  cachedDeobfuscator = null;
  return cachedDeobfuscator;
}

export interface DeobfuscationResult {
  path: string;
  code: string;
  changed: boolean;
}

export async function deobfuscateAndWrite(
  inputCode: string,
  baseDir: string,
  sourcePath: string,
  force: boolean,
  log: (message: string) => void,
  logError: (message: string, error?: unknown) => void
): Promise<DeobfuscationResult | null> {
  const deobfuscator = loadDeobfuscator();
  if (!deobfuscator) {
    log("Deobfuscator not available. Install javascript-deobfuscator to enable.");
    return null;
  }

  const outDir = path.join(baseDir, "deobfuscated");
  await ensureDir(outDir);
  const baseName = path.basename(sourcePath);
  const outPath = path.join(outDir, baseName);

  if (!force && fs.existsSync(outPath)) {
    const existing = await fs.promises.readFile(outPath, "utf8").catch(() => null);
    if (existing) {
      return { path: outPath, code: existing, changed: false };
    }
  }

  let output: string;
  try {
    output = deobfuscator(inputCode);
  } catch (error) {
    logError("Deobfuscation failed", error);
    return null;
  }

  if (!output || output.trim().length == 0) {
    return null;
  }

  const changed = output !== inputCode;
  try {
    await fs.promises.writeFile(outPath, output, "utf8");
  } catch (error) {
    logError("Failed to write deobfuscated output", error);
    return null;
  }

  return { path: outPath, code: output, changed };
}
