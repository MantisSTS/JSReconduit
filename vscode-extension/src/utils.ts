import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as vscode from "vscode";

export function expandHome(inputPath: string): string {
  if (!inputPath) {
    return inputPath;
  }
  if (inputPath.startsWith("~")) {
    return path.join(os.homedir(), inputPath.slice(1));
  }
  return inputPath;
}

export async function ensureDir(dirPath: string): Promise<void> {
  await fs.promises.mkdir(dirPath, { recursive: true });
}

export async function safeReadFile(filePath: string): Promise<string | null> {
  try {
    return await fs.promises.readFile(filePath, "utf8");
  } catch {
    return null;
  }
}

export function normalizePath(filePath: string): string {
  return path.resolve(filePath);
}

export function log(output: vscode.OutputChannel, message: string): void {
  output.appendLine(message);
}

export function logError(output: vscode.OutputChannel, message: string, error?: unknown): void {
  const detail = error instanceof Error ? error.message : String(error || "");
  output.appendLine(`[JSReconduit] ${message}${detail ? ": " + detail : ""}`);
}

export function toLocation(node: any): { line: number; column: number } | undefined {
  if (!node || !node.loc || !node.loc.start) {
    return undefined;
  }
  return {
    line: node.loc.start.line,
    column: node.loc.start.column + 1,
  };
}

export function isLikelyUrl(value: string): boolean {
  const lower = value.toLowerCase();
  return (
    lower.startsWith("http://") ||
    lower.startsWith("https://") ||
    lower.startsWith("ws://") ||
    lower.startsWith("wss://")
  );
}

export function isLikelyPath(value: string): boolean {
  if (value.startsWith("/") && value.length > 1) {
    return true;
  }
  if (value.includes("/") && !isLikelyUrl(value)) {
    return true;
  }
  return false;
}

export function extractQueryParams(value: string): string[] {
  const idx = value.indexOf("?");
  if (idx === -1) {
    return [];
  }
  const query = value.slice(idx + 1);
  const parts = query.split("&");
  const params: string[] = [];
  for (const part of parts) {
    const [name] = part.split("=");
    if (name) {
      params.push(name);
    }
  }
  return params;
}

export function isWordCandidate(value: string): boolean {
  if (value.length < 3 || value.length > 64) {
    return false;
  }
  for (const ch of value) {
    const code = ch.charCodeAt(0);
    const isAlphaNum =
      (code >= 48 && code <= 57) ||
      (code >= 65 && code <= 90) ||
      (code >= 97 && code <= 122) ||
      ch === "_" ||
      ch === "-";
    if (!isAlphaNum) {
      return false;
    }
  }
  return true;
}

export function splitPathSegments(value: string): string[] {
  const sanitized = value.replace("?", "/").replace("&", "/").replace("=", "/");
  return sanitized.split("/").filter(Boolean);
}
