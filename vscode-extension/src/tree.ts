import * as path from "path";
import * as vscode from "vscode";
import { URL } from "url";
import {
  AlertEntry,
  AssetAnalysis,
  CallGraphEdge,
  CoverageEntry,
  DriftEntry,
  EndpointCluster,
  Finding,
  FlowTrace,
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
  | { type: "diff"; drift: DriftEntry }
  | { type: "html"; html: { url: string; path: string; scripts: string[]; inline: number } }
  | { type: "htmlScript"; script: string; targetPath?: string }
  | { type: "sourcemap"; asset: AssetAnalysis; filePath: string }
  | { type: "cluster"; cluster: EndpointCluster }
  | { type: "trace"; trace: FlowTrace }
  | { type: "callGraphCaller"; caller: string; edges: CallGraphEdge[] }
  | { type: "callGraphEdge"; edge: CallGraphEdge }
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

  private formatLocation(finding: Finding): string {
    const line = finding.location?.line;
    const column = finding.location?.column;
    if (!line) {
      return "L?";
    }
    if (column) {
      return `L${line}:C${column}`;
    }
    return `L${line}`;
  }

  private formatFileLocation(finding: Finding): string {
    const base = path.basename(finding.filePath);
    const line = finding.location?.line;
    const column = finding.location?.column;
    if (!line) {
      return base;
    }
    if (column) {
      return `${base}:${line}:${column}`;
    }
    return `${base}:${line}`;
  }

  private sortFindings(findings: Finding[]): Finding[] {
    return findings.slice().sort((a, b) => a.label.localeCompare(b.label));
  }

  private formatTrace(trace: FlowTrace): string {
    return `${trace.source.label} → ${trace.sink.label}`;
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
      const analysis = element.asset.analysis;
      const total =
        analysis.endpoints.length +
        analysis.sinks.length +
        analysis.userSinks.length +
        analysis.secrets.length +
        analysis.signatures.length;
      item.description = `${total} findings`;
      item.command = {
        command: "jsreconduit.openLocation",
        title: "Open",
        arguments: [element.asset.analysisPath, 1, 1],
      };
      const htmlRefs = element.asset.htmlReferrers && element.asset.htmlReferrers.length
        ? `\nHTML: ${element.asset.htmlReferrers.join(", ")}`
        : "";
      item.tooltip = `${element.asset.asset.url}\n${element.asset.analysisPath}${htmlRefs}`;
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

    if (element.type === "diff") {
      const title = element.drift.url;
      const item = new vscode.TreeItem(title, vscode.TreeItemCollapsibleState.None);
      const from = element.drift.fromTimestamp || "?";
      const to = element.drift.toTimestamp || "?";
      item.description = `${from} → ${to}`;
      item.command = {
        command: "jsreconduit.openDiff",
        title: "Open Diff",
        arguments: [element.drift],
      };
      return item;
    }

    if (element.type === "html") {
      const item = new vscode.TreeItem(element.html.url, vscode.TreeItemCollapsibleState.Collapsed);
      const inline = element.html.inline ? `, inline: ${element.html.inline}` : "";
      item.description = `${element.html.scripts.length} scripts${inline}`;
      item.command = {
        command: "jsreconduit.openLocation",
        title: "Open",
        arguments: [element.html.path, 1, 1],
      };
      return item;
    }

    if (element.type === "htmlScript") {
      const item = new vscode.TreeItem(element.script, vscode.TreeItemCollapsibleState.None);
      if (element.targetPath) {
        item.description = path.basename(element.targetPath);
        item.command = {
          command: "jsreconduit.openLocation",
          title: "Open",
          arguments: [element.targetPath, 1, 1],
        };
      }
      return item;
    }

    if (element.type === "finding") {
      const item = new vscode.TreeItem(element.finding.label, vscode.TreeItemCollapsibleState.None);
      const locationText = this.formatFileLocation(element.finding);
      item.description = locationText;
      const detail = element.finding.detail ? `\nDetail: ${element.finding.detail}` : "";
      item.tooltip = `${element.finding.filePath}\n${this.formatLocation(element.finding)}${detail}`;
      const location = element.finding.location;
      item.command = {
        command: "jsreconduit.openLocation",
        title: "Open",
        arguments: [element.finding.filePath, location?.line || 1, location?.column || 1],
      };
      return item;
    }

    if (element.type === "cluster") {
      const label = `${element.cluster.basePath} (${element.cluster.authHint})`;
      const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.Collapsed);
      item.description = `${element.cluster.endpoints.length} endpoints`;
      return item;
    }

    if (element.type === "trace") {
      const item = new vscode.TreeItem(this.formatTrace(element.trace), vscode.TreeItemCollapsibleState.None);
      const location = element.trace.sink.location;
      item.description = location ? `L${location.line}` : "L?";
      item.tooltip = element.trace.path.join(" → ");
      item.command = {
        command: "jsreconduit.openLocation",
        title: "Open",
        arguments: [
          element.trace.filePath,
          location?.line || 1,
          location?.column || 1,
        ],
      };
      return item;
    }

    if (element.type === "callGraphCaller") {
      const item = new vscode.TreeItem(element.caller, vscode.TreeItemCollapsibleState.Collapsed);
      item.description = `${element.edges.length} calls`;
      return item;
    }

    if (element.type === "callGraphEdge") {
      const item = new vscode.TreeItem(element.edge.callee, vscode.TreeItemCollapsibleState.None);
      const location = element.edge.location;
      item.description = location ? `L${location.line}` : "L?";
      item.command = {
        command: "jsreconduit.openLocation",
        title: "Open",
        arguments: [
          element.edge.filePath,
          location?.line || 1,
          location?.column || 1,
        ],
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
      const counts = {
        assets: this.snapshot.assets.filter((asset) => asset.asset.asset_type !== "html").length,
        html: this.snapshot.htmlAssets.length,
        routes: this.snapshot.routes.length,
        drift: this.snapshot.drift.length,
        diffs: this.snapshot.drift.filter((entry) => entry.fromPath && entry.toPath).length,
        alerts: this.snapshot.alerts.length,
        triage: this.snapshot.triage.length,
        coverage: this.snapshot.coverage.coverage.length,
        data: this.snapshot.data.length,
        paths: this.snapshot.paths.length,
        urls: this.snapshot.urls.length,
        hostnames: this.snapshot.hostnames.length,
        extensions: this.snapshot.extensions.length,
        mimeTypes: this.snapshot.mimeTypes.length,
        regexes: this.snapshot.regexes.length,
        graphql: this.snapshot.graphql.length,
        events: this.snapshot.events.length,
        location: this.snapshot.location.length,
        storage: this.snapshot.storage.length,
        cookies: this.snapshot.cookies.length,
        documentDomain: this.snapshot.documentDomain.length,
        windowName: this.snapshot.windowName.length,
        windowOpen: this.snapshot.windowOpen.length,
        urlSearchParams: this.snapshot.urlSearchParams.length,
        restClient: this.snapshot.restClient.length,
        fetchOptions: this.snapshot.fetchOptions.length,
        schemas: this.snapshot.schemas.length,
        dependencies: this.snapshot.dependencies.length,
        featureFlags: this.snapshot.featureFlags.length,
        endpoints: this.snapshot.endpoints.length,
        sinks: this.snapshot.sinks.length,
        userSinks: this.snapshot.userSinks.length,
        secrets: this.snapshot.secrets.length,
        signatures: this.snapshot.signatures.length,
        frameworks: this.snapshot.frameworks.length,
        clusters: this.snapshot.clusters.length,
        traces: this.snapshot.traces.length,
        callGraph: this.snapshot.callGraph.length,
        sourcemaps: this.snapshot.sourcemaps.length,
        wordlist: this.snapshot.wordlist.length,
      };
      return Promise.resolve([
        { type: "root", id: "assets", label: `Captured Files (${counts.assets})` },
        { type: "root", id: "html", label: `HTML (${counts.html})` },
        { type: "root", id: "routes", label: `Routes (${counts.routes})` },
        { type: "root", id: "drift", label: `Drift (${counts.drift})` },
        { type: "root", id: "diffs", label: `Diffs (${counts.diffs})` },
        { type: "root", id: "alerts", label: `Alerts (${counts.alerts})` },
        { type: "root", id: "triage", label: `Triage (${counts.triage})` },
        { type: "root", id: "coverage", label: `Coverage (${counts.coverage})` },
        { type: "root", id: "clusters", label: `Clusters (${counts.clusters})` },
        { type: "root", id: "data", label: `Data (${counts.data})` },
        { type: "root", id: "paths", label: `Paths (${counts.paths})` },
        { type: "root", id: "urls", label: `URLs (${counts.urls})` },
        { type: "root", id: "hostnames", label: `Hostnames (${counts.hostnames})` },
        { type: "root", id: "extensions", label: `Extensions (${counts.extensions})` },
        { type: "root", id: "mime-types", label: `MIME Types (${counts.mimeTypes})` },
        { type: "root", id: "regex", label: `Regex (${counts.regexes})` },
        { type: "root", id: "graphql", label: `GraphQL (${counts.graphql})` },
        { type: "root", id: "events", label: `Events (${counts.events})` },
        { type: "root", id: "location", label: `Location (${counts.location})` },
        { type: "root", id: "storage", label: `Storage (${counts.storage})` },
        { type: "root", id: "cookies", label: `Cookies (${counts.cookies})` },
        { type: "root", id: "document-domain", label: `Document Domain (${counts.documentDomain})` },
        { type: "root", id: "window-name", label: `Window Name (${counts.windowName})` },
        { type: "root", id: "window-open", label: `Window Open (${counts.windowOpen})` },
        { type: "root", id: "urlsearchparams", label: `URLSearchParams (${counts.urlSearchParams})` },
        { type: "root", id: "rest-client", label: `Rest Client (${counts.restClient})` },
        { type: "root", id: "fetch-options", label: `Fetch Options (${counts.fetchOptions})` },
        { type: "root", id: "schemas", label: `Schemas (${counts.schemas})` },
        { type: "root", id: "dependencies", label: `Dependencies (${counts.dependencies})` },
        { type: "root", id: "feature-flags", label: `Feature Flags (${counts.featureFlags})` },
        { type: "root", id: "endpoints", label: `Endpoints (${counts.endpoints})` },
        { type: "root", id: "sinks", label: `Sinks (${counts.sinks})` },
        { type: "root", id: "user-sinks", label: `User Sinks (${counts.userSinks})` },
        { type: "root", id: "secrets", label: `Secrets (${counts.secrets})` },
        { type: "root", id: "signatures", label: `Signatures (${counts.signatures})` },
        { type: "root", id: "frameworks", label: `Frameworks (${counts.frameworks})` },
        { type: "root", id: "traces", label: `Traces (${counts.traces})` },
        { type: "root", id: "call-graph", label: `Call Graph (${counts.callGraph})` },
        { type: "root", id: "sourcemaps", label: `Sourcemaps (${counts.sourcemaps})` },
        { type: "root", id: "wordlist", label: `Wordlist (${counts.wordlist})` },
      ]);
    }

    if (element.type === "root") {
      switch (element.id) {
        case "assets":
          return Promise.resolve(
            this.snapshot.assets
              .filter((asset) => asset.asset.asset_type !== "html")
              .map((asset) => ({ type: "asset", asset }))
          );
        case "html":
          return Promise.resolve(
            this.snapshot.htmlAssets.map((entry) => ({
              type: "html",
              html: {
                url: entry.asset.url,
                path: entry.htmlPath,
                scripts: entry.scriptSrcs,
                inline: entry.inlineScripts,
              },
            }))
          );
        case "routes":
          return Promise.resolve(this.snapshot.routes.map((route) => ({ type: "route", route })));
        case "drift":
          return Promise.resolve(this.snapshot.drift.map((drift) => ({ type: "drift", drift })));
        case "diffs":
          return Promise.resolve(
            this.snapshot.drift
              .filter((entry) => entry.fromPath && entry.toPath)
              .map((drift) => ({ type: "diff", drift }))
          );
        case "alerts":
          return Promise.resolve(this.snapshot.alerts.map((alert) => ({ type: "alert", alert })));
        case "triage":
          return Promise.resolve(this.snapshot.triage.map((triage) => ({ type: "triage", triage })));
        case "coverage":
          return Promise.resolve(this.snapshot.coverage.coverage.map((coverage) => ({ type: "coverage", coverage })));
        case "clusters":
          return Promise.resolve(this.snapshot.clusters.map((cluster) => ({ type: "cluster", cluster })));
        case "data":
          return Promise.resolve(this.sortFindings(this.snapshot.data).map((finding) => ({ type: "finding", finding })));
        case "paths":
          return Promise.resolve(this.sortFindings(this.snapshot.paths).map((finding) => ({ type: "finding", finding })));
        case "urls":
          return Promise.resolve(this.sortFindings(this.snapshot.urls).map((finding) => ({ type: "finding", finding })));
        case "hostnames":
          return Promise.resolve(
            this.sortFindings(this.snapshot.hostnames).map((finding) => ({ type: "finding", finding }))
          );
        case "extensions":
          return Promise.resolve(
            this.sortFindings(this.snapshot.extensions).map((finding) => ({ type: "finding", finding }))
          );
        case "mime-types":
          return Promise.resolve(
            this.sortFindings(this.snapshot.mimeTypes).map((finding) => ({ type: "finding", finding }))
          );
        case "regex":
          return Promise.resolve(
            this.sortFindings(this.snapshot.regexes).map((finding) => ({ type: "finding", finding }))
          );
        case "graphql":
          return Promise.resolve(
            this.sortFindings(this.snapshot.graphql).map((finding) => ({ type: "finding", finding }))
          );
        case "events":
          return Promise.resolve(
            this.sortFindings(this.snapshot.events).map((finding) => ({ type: "finding", finding }))
          );
        case "location":
          return Promise.resolve(
            this.sortFindings(this.snapshot.location).map((finding) => ({ type: "finding", finding }))
          );
        case "storage":
          return Promise.resolve(
            this.sortFindings(this.snapshot.storage).map((finding) => ({ type: "finding", finding }))
          );
        case "cookies":
          return Promise.resolve(
            this.sortFindings(this.snapshot.cookies).map((finding) => ({ type: "finding", finding }))
          );
        case "document-domain":
          return Promise.resolve(
            this.sortFindings(this.snapshot.documentDomain).map((finding) => ({ type: "finding", finding }))
          );
        case "window-name":
          return Promise.resolve(
            this.sortFindings(this.snapshot.windowName).map((finding) => ({ type: "finding", finding }))
          );
        case "window-open":
          return Promise.resolve(
            this.sortFindings(this.snapshot.windowOpen).map((finding) => ({ type: "finding", finding }))
          );
        case "urlsearchparams":
          return Promise.resolve(
            this.sortFindings(this.snapshot.urlSearchParams).map((finding) => ({ type: "finding", finding }))
          );
        case "rest-client":
          return Promise.resolve(
            this.sortFindings(this.snapshot.restClient).map((finding) => ({ type: "finding", finding }))
          );
        case "fetch-options":
          return Promise.resolve(
            this.sortFindings(this.snapshot.fetchOptions).map((finding) => ({ type: "finding", finding }))
          );
        case "schemas":
          return Promise.resolve(
            this.sortFindings(this.snapshot.schemas).map((finding) => ({ type: "finding", finding }))
          );
        case "dependencies":
          return Promise.resolve(
            this.sortFindings(this.snapshot.dependencies).map((finding) => ({ type: "finding", finding }))
          );
        case "feature-flags":
          return Promise.resolve(
            this.sortFindings(this.snapshot.featureFlags).map((finding) => ({ type: "finding", finding }))
          );
        case "endpoints":
          return Promise.resolve(this.sortFindings(this.snapshot.endpoints).map((finding) => ({ type: "finding", finding })));
        case "sinks":
          return Promise.resolve(this.sortFindings(this.snapshot.sinks).map((finding) => ({ type: "finding", finding })));
        case "user-sinks":
          return Promise.resolve(this.sortFindings(this.snapshot.userSinks).map((finding) => ({ type: "finding", finding })));
        case "secrets":
          return Promise.resolve(this.sortFindings(this.snapshot.secrets).map((finding) => ({ type: "finding", finding })));
        case "signatures":
          return Promise.resolve(this.sortFindings(this.snapshot.signatures).map((finding) => ({ type: "finding", finding })));
        case "frameworks":
          return Promise.resolve(this.sortFindings(this.snapshot.frameworks).map((finding) => ({ type: "finding", finding })));
        case "traces":
          return Promise.resolve(
            this.snapshot.traces
              .slice()
              .sort((a, b) => this.formatTrace(a).localeCompare(this.formatTrace(b)))
              .map((trace) => ({ type: "trace", trace }))
          );
        case "call-graph": {
          const grouped = new Map<string, CallGraphEdge[]>();
          for (const edge of this.snapshot.callGraph) {
            if (!grouped.has(edge.caller)) {
              grouped.set(edge.caller, []);
            }
            grouped.get(edge.caller)!.push(edge);
          }
          const nodes: TreeNode[] = [];
          for (const [caller, edges] of grouped.entries()) {
            nodes.push({ type: "callGraphCaller", caller, edges });
          }
          nodes.sort((a, b) => {
            if (a.type !== "callGraphCaller" || b.type !== "callGraphCaller") {
              return 0;
            }
            return a.caller.localeCompare(b.caller);
          });
          return Promise.resolve(nodes);
        }
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

    if (element.type === "html") {
      const nodes: TreeNode[] = [];
      for (const script of element.html.scripts) {
        const resolved = this.resolveScriptUrl(element.html.url, script);
        let targetPath: string | undefined;
        if (resolved) {
          const match = this.snapshot.assets.find(
            (asset) => asset.asset.asset_type !== "html" && asset.asset.url === resolved
          );
          if (match) {
            targetPath = match.analysisPath;
          }
        }
        nodes.push({ type: "htmlScript", script, targetPath });
      }
      return Promise.resolve(nodes);
    }

    if (element.type === "cluster") {
      return Promise.resolve(
        this.sortFindings(element.cluster.endpoints).map((finding) => ({ type: "finding", finding }))
      );
    }

    if (element.type === "callGraphCaller") {
      return Promise.resolve(element.edges.map((edge) => ({ type: "callGraphEdge", edge })));
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

  private resolveScriptUrl(baseUrl: string, script: string): string | null {
    if (!script) {
      return null;
    }
    if (script.startsWith("http://") || script.startsWith("https://")) {
      return script;
    }
    if (script.startsWith("//")) {
      try {
        const base = new URL(baseUrl);
        return `${base.protocol}${script}`;
      } catch {
        return null;
      }
    }
    try {
      return new URL(script, baseUrl).toString();
    } catch {
      return null;
    }
  }
}
