import * as fs from "fs";
import * as path from "path";
import { ensureDir } from "./utils";

export async function writeWordlist(
  baseDir: string,
  words: Set<string>,
  overridePath?: string
): Promise<string> {
  const targetPath = overridePath && overridePath.length > 0
    ? overridePath
    : path.join(baseDir, "wordlists", "jsreconduit-wordlist.txt");
  await ensureDir(path.dirname(targetPath));
  const entries = Array.from(words).sort();
  await fs.promises.writeFile(targetPath, entries.join("\n") + "\n", "utf8");
  return targetPath;
}
