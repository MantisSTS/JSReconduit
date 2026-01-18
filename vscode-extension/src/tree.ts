import * as path from "path";
import * as vscode from "vscode";
import {
  AlertEntry,
  AssetAnalysis,
  CoverageEntry,
  DriftEntry,
  Finding,
  RouteEntry,
  StoreSnapshot,
  TriageEntry,
} from "./types";

export type TreeNode =
  | { type: "root"; id: string; label: string }
  | { type: "asset"; asset: AssetAnalysis }
  | { type: "finding"; finding: Finding }
  | { type: "coverage"; coverage: CoverageEntry }
  | { type: "triage"; triage: TriageEntry }
  | { type: "alert"; alert: AlertEntry }
  | { type: "route"; route: RouteEntry }
  | { type: "drift"; drift: DriftEntry }
  | { type: "sourcemap"; asset: AssetAnalysis; filePath: string }
  | { type: "word"; value: string }
  | { type: "wordlistAction" };

export class JSReconduitTreeProvider implements vscode.TreeDataProvider<TreeNode> {
  private _onDidChangeTreeData = new vscode.EventEmitter<TreeNode | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private snapshot: StoreSnapshot;

  constructor(snapshot: StoreSnapshot) {
    this.snapshot = snapshot;
  }

  update(snapshot: StoreSnapshot): void {
    this.snapshot = snapshot;
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    if (element.type === "root") {
      const item = new vscode.TreeItem(element.label, vscode.TreeItemCollapsibleState.Collapsed);
      item.contextValue = element.id;
      return item;
    }

    if (element.type === "asset") {
      const label = element.asset.asset.original_filename || path.basename(element.asset.analysisPath);
      const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
      item.description = element.asset.asset.url;
      item.command = {
        command: "jsreconduit.openLocation",
        title: "Open",
        arguments: [element.asset.analysisPath, 1, 1],
      };
      return item;
    }

    if (element.type === "route") {
      const item = new vscode.TreeItem(element.route.route, vscode.TreeItemCollapsibleState.Collapsed);
      item.description = `${element.route.assets.length} assets`;
      return item;
    }

    if (element.type === "coverage") {
      const item = new vscode.TreeItem(element.coverage.label, vscode.TreeItemCollapsibleState.None);
      item.description = `T:${element.coverage.total} E:${element.coverage.endpoints} S:${element.coverage.sinks} U:${element.coverage.userSinks} K:${element.coverage.secrets} G:${element.coverage.signatures}`;
      return item;
    }

    if (element.type === "triage") {
      const item = new vscode.TreeItem(
        `${element.triage.severity} (${element.triage.score}) ${element.triage.url}`,
        vscode.TreeItemCollapsibleState.None
      );
      item.description = element.triage.reasons.join(", ");
      item.command = {
        command: "jsreconduit.openLocation",
        title: "Open",
        arguments: [element.triage.filePath, 1, 1],
      };
      return item;
    }

    if (element.type === "alert") {
      const item = new vscode.TreeItem(
        `${element.alert.severity} ${element.alert.summary}`,
        vscode.TreeItemCollapsibleState.None
      );
      item.description = element.alert.details.join(", ");
      return item;
    }

    if (element.type === "drift") {
      const item = new vscode.TreeItem(element.drift.url, vscode.TreeItemCollapsibleState.Collapsed);
      const added = element.drift.added;
      const total =
        added.endpoints.length +
        added.sinks.length +
        added.userSinks.length +
        added.secrets.length +
        added.paths.length +
        added.urls.length;
      item.description = `${total} new findings`;
      return item;
    }

    if (element.type === "finding") {
      const item = new vscode.TreeItem(element.finding.label, vscode.TreeItemCollapsibleState.None);
      if (element.finding.detail) {
        item.description = element.finding.detail;
      }
      const location = element.finding.location;
      item.command = {
        command: "jsreconduit.openLocation",
        title: "Open",
        arguments: [element.finding.filePath, location?.line || 1, location?.column || 1],
      };
      return item;
    }

    if (element.type === "sourcemap") {
      const item = new vscode.TreeItem(path.basename(element.filePath), vscode.TreeItemCollapsibleState.None);
      const stats = element.asset.sourcemap?.resolvedStats?.[element.filePath];
      if (stats) {
        item.description = `E:${stats.endpoints} S:${stats.sinks} U:${stats.userSinks} K:${stats.secrets}`;
      } else {
        item.description = element.asset.asset.url;
      }
      item.command = {
        command: "jsreconduit.openLocation",
        title: "Open",
        arguments: [element.filePath, 1, 1],
      };
      return item;
    }

    if (element.type === "wordlistAction") {
      const item = new vscode.TreeItem("Export Wordlist", vscode.TreeItemCollapsibleState.None);
      item.command = {
        command: "jsreconduit.exportWordlist",
        title: "Export Wordlist",
      };
      item.iconPath = new vscode.ThemeIcon("cloud-download");
      return item;
    }

    const wordItem = new vscode.TreeItem(element.value, vscode.TreeItemCollapsibleState.None);
    return wordItem;
  }

  getChildren(element?: TreeNode): Thenable<TreeNode[]> {
    if (!element) {
      return Promise.resolve([
        { type: "root", id: "assets", label: "Captured Files" },
        { type: "root", id: "routes", label: "Routes" },
        { type: "root", id: "drift", label: "Drift" },
        { type: "root", id: "alerts", label: "Alerts" },
        { type: "root", id: "triage", label: "Triage" },
        { type: "root", id: "coverage", label: "Coverage" },
        { type: "root", id: "endpoints", label: "Endpoints" },
        { type: "root", id: "sinks", label: "Sinks" },
        { type: "root", id: "user-sinks", label: "User Sinks" },
        { type: "root", id: "secrets", label: "Secrets" },
        { type: "root", id: "signatures", label: "Signatures" },
        { type: "root", id: "frameworks", label: "Frameworks" },
        { type: "root", id: "sourcemaps", label: "Sourcemaps" },
        { type: "root", id: "wordlist", label: "Wordlist" },
      ]);
    }

    if (element.type === "root") {
      switch (element.id) {
        case "assets":
          return Promise.resolve(this.snapshot.assets.map((asset) => ({ type: "asset", asset })));
        case "routes":
          return Promise.resolve(this.snapshot.routes.map((route) => ({ type: "route", route })));
        case "drift":
          return Promise.resolve(this.snapshot.drift.map((drift) => ({ type: "drift", drift })));
        case "alerts":
          return Promise.resolve(this.snapshot.alerts.map((alert) => ({ type: "alert", alert })));
        case "triage":
          return Promise.resolve(this.snapshot.triage.map((triage) => ({ type: "triage", triage })));
        case "coverage":
          return Promise.resolve(this.snapshot.coverage.coverage.map((coverage) => ({ type: "coverage", coverage })));
        case "endpoints":
          return Promise.resolve(this.snapshot.endpoints.map((finding) => ({ type: "finding", finding })));
        case "sinks":
          return Promise.resolve(this.snapshot.sinks.map((finding) => ({ type: "finding", finding })));
        case "user-sinks":
          return Promise.resolve(this.snapshot.userSinks.map((finding) => ({ type: "finding", finding })));
        case "secrets":
          return Promise.resolve(this.snapshot.secrets.map((finding) => ({ type: "finding", finding })));
        case "signatures":
          return Promise.resolve(this.snapshot.signatures.map((finding) => ({ type: "finding", finding })));
        case "frameworks":
          return Promise.resolve(this.snapshot.frameworks.map((finding) => ({ type: "finding", finding })));
        case "sourcemaps": {
          const nodes: TreeNode[] = [];
          for (const entry of this.snapshot.sourcemaps) {
            for (const filePath of entry.files) {
              nodes.push({ type: "sourcemap", asset: entry.asset, filePath });
            }
          }
          return Promise.resolve(nodes);
        }
        case "wordlist": {
          const entries = this.snapshot.wordlist.slice(0, 200);
          const nodes: TreeNode[] = [{ type: "wordlistAction" }];
          for (const value of entries) {
            nodes.push({ type: "word", value });
          }
          return Promise.resolve(nodes);
        }
        default:
          return Promise.resolve([]);
      }
    }

    if (element.type === "route") {
      return Promise.resolve(element.route.assets.map((asset) => ({ type: "asset", asset })));
    }

    if (element.type === "drift") {
      const findings: Finding[] = [];
      const added = element.drift.added;
      findings.push(...this.decorateFindings(added.endpoints, "endpoint"));
      findings.push(...this.decorateFindings(added.sinks, "sink"));
      findings.push(...this.decorateFindings(added.userSinks, "user_sink"));
      findings.push(...this.decorateFindings(added.secrets, "secret"));
      findings.push(...this.decorateFindings(added.paths, "path"));
      findings.push(...this.decorateFindings(added.urls, "url"));
      return Promise.resolve(findings.map((finding) => ({ type: "finding", finding })));
    }

    return Promise.resolve([]);
  }

  private decorateFindings(findings: Finding[], category: string): Finding[] {
    return findings.map((finding) => ({
      ...finding,
      detail: finding.detail ? `${category}: ${finding.detail}` : category,
    }));
  }
}
