import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { AssetIndexEntry } from "./types";
import { ensureDir, expandHome, logError } from "./utils";

export class IndexLoader {
  private output: vscode.OutputChannel;
  private lastGood: AssetIndexEntry[] = [];

  constructor(output: vscode.OutputChannel) {
    this.output = output;
  }

  async load(baseDir: string): Promise<AssetIndexEntry[]> {
    const indexPath = path.join(baseDir, "index.json");
    try {
      const raw = await fs.promises.readFile(indexPath, "utf8");
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) {
        return this.lastGood;
      }
      this.lastGood = parsed as AssetIndexEntry[];
      return this.lastGood;
    } catch (error) {
      logError(this.output, "Failed to read index.json", error);
      return this.lastGood;
    }
  }
}

export class ProjectWatcher {
  private baseDir: string;
  private output: vscode.OutputChannel;
  private onChange: () => void;
  private watchers: fs.FSWatcher[] = [];
  private debounceTimer?: NodeJS.Timeout;

  constructor(baseDir: string, onChange: () => void, output: vscode.OutputChannel) {
    this.baseDir = expandHome(baseDir);
    this.onChange = onChange;
    this.output = output;
  }

  async start(): Promise<void> {
    await ensureDir(this.baseDir);
    await ensureDir(path.join(this.baseDir, "raw"));
    await ensureDir(path.join(this.baseDir, "beautified"));
    await ensureDir(path.join(this.baseDir, "sourcemaps"));
    await ensureDir(path.join(this.baseDir, "resolved"));
    const indexPath = path.join(this.baseDir, "index.json");
    if (!fs.existsSync(indexPath)) {
      await fs.promises.writeFile(indexPath, "[]", "utf8");
    }
    const watchTargets = [indexPath, path.join(this.baseDir, "raw"), path.join(this.baseDir, "beautified")];

    for (const target of watchTargets) {
      try {
        await ensureDir(path.dirname(target));
        const watcher = fs.watch(target, { persistent: true }, () => this.queueChange());
        this.watchers.push(watcher);
      } catch (error) {
        logError(this.output, `Failed to watch ${target}`, error);
      }
    }
  }

  updateBaseDir(baseDir: string): void {
    this.dispose();
    this.baseDir = expandHome(baseDir);
    this.start().then(() => this.queueChange());
  }

  private queueChange(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }
    this.debounceTimer = setTimeout(() => {
      this.onChange();
    }, 500);
  }

  dispose(): void {
    for (const watcher of this.watchers) {
      watcher.close();
    }
    this.watchers = [];
  }
}
