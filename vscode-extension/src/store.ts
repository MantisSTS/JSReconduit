import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { analyzeJavaScript } from "./analyzer";
import { deobfuscateAndWrite } from "./deobfuscator";
import { IndexLoader } from "./indexer";
import { writeInterestingOutputs } from "./interesting";
import { loadSignatureRules } from "./signatures";
import { resolveSourcemap } from "./sourcemap";
import {
  AssetAnalysis,
  AssetIndexEntry,
  Finding,
  StoreSnapshot,
  RouteEntry,
  DriftEntry,
  SourcemapGraphEntry,
  SourcemapStats,
  CoverageSummary,
  CoverageEntry,
  TriageEntry,
  AlertEntry,
  SignatureRule,
  EndpointCluster,
  CallGraphEdge,
  FlowTrace,
} from "./types";
import { logError, log, normalizePath } from "./utils";

export class JSReconduitStore {
  private output: vscode.OutputChannel;
  private loader: IndexLoader;
  private assets: AssetAnalysis[] = [];

  constructor(output: vscode.OutputChannel) {
    this.output = output;
    this.loader = new IndexLoader(output);
  }

  async refresh(
    baseDir: string,
    options?: {
      autoDeobfuscate?: boolean;
      preferDeobfuscated?: boolean;
      forceDeobfuscate?: boolean;
      signaturePath?: string;
    }
  ): Promise<void> {
    const entries = await this.loader.load(baseDir);
    const results: AssetAnalysis[] = [];
    const autoDeobfuscate = options?.autoDeobfuscate ?? false;
    const preferDeobfuscated = options?.preferDeobfuscated ?? false;
    const forceDeobfuscate = options?.forceDeobfuscate ?? false;
    const signaturePath = options?.signaturePath;
    const signatureRules = await loadSignatureRules(baseDir, signaturePath, (message, error) =>
      logError(this.output, message, error)
    );

    for (const entry of entries) {
      const analysisPath = this.pickAnalysisPath(entry, baseDir, preferDeobfuscated);
      if (!analysisPath) {
        continue;
      }
      const sourceContents = await fs.promises.readFile(analysisPath, "utf8").catch(() => null);
      if (!sourceContents) {
        continue;
      }
      let analysisContents = sourceContents;
      let analysisFilePath = analysisPath;

      if (autoDeobfuscate) {
        const deob = await deobfuscateAndWrite(
          analysisContents,
          baseDir,
          analysisPath,
          forceDeobfuscate,
          (message) => log(this.output, message),
          (message, error) => logError(this.output, message, error)
        );
        if (deob) {
          analysisContents = deob.code;
          analysisFilePath = deob.path;
        }
      }

      const analysis = analyzeJavaScript(analysisContents, analysisFilePath, signatureRules);
      const asset: AssetAnalysis = {
        asset: entry,
        analysis,
        analysisPath: analysisFilePath,
      };

      const sourcemap = await resolveSourcemap(entry, sourceContents, baseDir, (message, error) =>
        logError(this.output, message, error)
      );
      if (sourcemap) {
        const resolvedStats = await this.analyzeResolvedSources(sourcemap.resolvedFiles, signatureRules);
        if (Object.keys(resolvedStats).length > 0) {
          sourcemap.resolvedStats = resolvedStats;
        }
        asset.sourcemap = sourcemap;
      }

      results.push(asset);
    }

    this.assets = results;
    await writeInterestingOutputs(baseDir, this.snapshot()).catch((error) =>
      logError(this.output, "Failed to write interesting outputs", error)
    );
    log(this.output, `JSReconduit: Loaded ${results.length} assets.`);
  }

  snapshot(): StoreSnapshot {
    const endpoints: Finding[] = [];
    const sinks: Finding[] = [];
    const userSinks: Finding[] = [];
    const frameworks: Finding[] = [];
    const secrets: Finding[] = [];
    const signatures: Finding[] = [];
    const sourcemaps: { asset: AssetAnalysis; files: string[] }[] = [];
    const wordlist = new Set<string>();
    const callGraph: CallGraphEdge[] = [];
    const traces: FlowTrace[] = [];

    for (const asset of this.assets) {
      endpoints.push(...asset.analysis.endpoints);
      sinks.push(...asset.analysis.sinks);
      userSinks.push(...asset.analysis.userSinks);
      frameworks.push(...asset.analysis.frameworks);
      secrets.push(...asset.analysis.secrets);
      signatures.push(...asset.analysis.signatures);
      callGraph.push(...asset.analysis.callGraph);
      traces.push(...asset.analysis.traces);
      for (const word of asset.analysis.wordlist) {
        wordlist.add(word);
      }
      if (asset.sourcemap) {
        sourcemaps.push({ asset, files: asset.sourcemap.resolvedFiles });
      }
    }

    const routes = this.buildRoutes();
    const drift = this.buildDrift();
    const coverage = this.buildCoverage();
    const triage = this.buildTriage(coverage);
    const alerts = this.buildAlerts(drift);
    const clusters = this.buildEndpointClusters();

    return {
      assets: this.assets,
      endpoints,
      sinks,
      userSinks,
      frameworks,
      secrets,
      signatures,
      routes,
      drift,
      alerts,
      triage,
      coverage,
      clusters,
      callGraph,
      traces,
      sourcemapGraph: this.buildSourcemapGraph(),
      sourcemaps,
      wordlist: Array.from(wordlist).sort(),
    };
  }

  private pickAnalysisPath(entry: AssetIndexEntry, baseDir: string, preferDeobfuscated: boolean): string | null {
    if (preferDeobfuscated) {
      const deob = this.getDeobfuscatedPath(entry, baseDir);
      if (deob && fs.existsSync(deob)) {
        return deob;
      }
    }
    const beautified = entry.beautified_path ? normalizePath(entry.beautified_path) : "";
    if (beautified && fs.existsSync(beautified)) {
      return beautified;
    }
    const raw = entry.raw_path ? normalizePath(entry.raw_path) : "";
    if (raw && fs.existsSync(raw)) {
      return raw;
    }
    return null;
  }

  private getDeobfuscatedPath(entry: AssetIndexEntry, baseDir: string): string | null {
    const sourcePath = entry.beautified_path || entry.raw_path;
    if (!sourcePath) {
      return null;
    }
    const baseName = path.basename(sourcePath);
    return path.join(baseDir, "deobfuscated", baseName);
  }

  private async analyzeResolvedSources(
    files: string[],
    signatureRules: SignatureRule[]
  ): Promise<Record<string, SourcemapStats>> {
    const stats: Record<string, SourcemapStats> = {};
    for (const filePath of files) {
      const contents = await fs.promises.readFile(filePath, "utf8").catch(() => null);
      if (!contents) {
        continue;
      }
      const analysis = analyzeJavaScript(contents, filePath, signatureRules);
      stats[filePath] = {
        endpoints: analysis.endpoints.length,
        sinks: analysis.sinks.length,
        userSinks: analysis.userSinks.length,
        secrets: analysis.secrets.length,
      };
    }
    return stats;
  }

  private buildRoutes(): RouteEntry[] {
    const routeMap = new Map<string, Map<string, AssetAnalysis>>();
    for (const asset of this.assets) {
      const referers = new Set<string>();
      if (asset.asset.referer) {
        referers.add(asset.asset.referer);
      }
      if (asset.asset.observations) {
        for (const obs of asset.asset.observations) {
          if (obs.referer) {
            referers.add(obs.referer);
          }
        }
      }
      for (const route of referers) {
        if (!routeMap.has(route)) {
          routeMap.set(route, new Map());
        }
        routeMap.get(route)!.set(asset.asset.sha256, asset);
      }
    }
    const entries: RouteEntry[] = [];
    for (const [route, assets] of routeMap.entries()) {
      entries.push({ route, assets: Array.from(assets.values()) });
    }
    entries.sort((a, b) => a.route.localeCompare(b.route));
    return entries;
  }

  private buildDrift(): DriftEntry[] {
    const byUrl = new Map<string, AssetAnalysis[]>();
    for (const asset of this.assets) {
      if (!byUrl.has(asset.asset.url)) {
        byUrl.set(asset.asset.url, []);
      }
      byUrl.get(asset.asset.url)!.push(asset);
    }

    const drift: DriftEntry[] = [];
    for (const [url, assets] of byUrl.entries()) {
      if (assets.length < 2) {
        continue;
      }
      assets.sort((a, b) => (a.asset.timestamp || "").localeCompare(b.asset.timestamp || ""));
      const previous = assets[assets.length - 2];
      const current = assets[assets.length - 1];
      const added = {
        endpoints: this.diffFindings(current.analysis.endpoints, previous.analysis.endpoints),
        sinks: this.diffFindings(current.analysis.sinks, previous.analysis.sinks),
        userSinks: this.diffFindings(current.analysis.userSinks, previous.analysis.userSinks),
        secrets: this.diffFindings(current.analysis.secrets, previous.analysis.secrets),
        paths: this.diffFindings(current.analysis.paths, previous.analysis.paths),
        urls: this.diffFindings(current.analysis.urls, previous.analysis.urls),
      };
      const hasChanges =
        added.endpoints.length ||
        added.sinks.length ||
        added.userSinks.length ||
        added.secrets.length ||
        added.paths.length ||
        added.urls.length;
      if (!hasChanges) {
        continue;
      }
      drift.push({
        url,
        fromTimestamp: previous.asset.timestamp,
        toTimestamp: current.asset.timestamp,
        fromPath: previous.analysisPath,
        toPath: current.analysisPath,
        added,
      });
    }
    drift.sort((a, b) => a.url.localeCompare(b.url));
    return drift;
  }

  private diffFindings(current: Finding[], previous: Finding[]): Finding[] {
    const prevSet = new Set(previous.map((finding) => finding.label));
    return current.filter((finding) => !prevSet.has(finding.label));
  }

  private buildSourcemapGraph(): SourcemapGraphEntry[] {
    const graph: SourcemapGraphEntry[] = [];
    for (const asset of this.assets) {
      const sourcemap = asset.sourcemap;
      if (!sourcemap || !sourcemap.resolvedStats) {
        continue;
      }
      const resolved = Object.entries(sourcemap.resolvedStats).map(([filePath, stats]) => ({
        filePath,
        endpoints: stats.endpoints,
        sinks: stats.sinks,
        userSinks: stats.userSinks,
        secrets: stats.secrets,
      }));
      graph.push({
        assetUrl: asset.asset.url,
        assetPath: asset.analysisPath,
        sourcemapPath: sourcemap.sourcemapPath,
        resolved,
      });
    }
    return graph;
  }

  private buildCoverage(): CoverageSummary {
    const coverage: CoverageEntry[] = [];
    let totalEndpoints = 0;
    let totalSinks = 0;
    let totalUserSinks = 0;
    let totalSecrets = 0;
    let totalSignatures = 0;

    for (const asset of this.assets) {
      const endpoints = asset.analysis.endpoints.length;
      const sinks = asset.analysis.sinks.length;
      const userSinks = asset.analysis.userSinks.length;
      const secrets = asset.analysis.secrets.length;
      const signaturesCount = asset.analysis.signatures.length;
      const total = endpoints + sinks + userSinks + secrets + signaturesCount;
      coverage.push({
        label: asset.asset.url,
        endpoints,
        sinks,
        userSinks,
        secrets,
        signatures: signaturesCount,
        total,
      });
      totalEndpoints += endpoints;
      totalSinks += sinks;
      totalUserSinks += userSinks;
      totalSecrets += secrets;
      totalSignatures += signaturesCount;
    }

    coverage.sort((a, b) => b.total - a.total);
    return {
      assets: this.assets.length,
      routes: this.buildRoutes().length,
      coverage,
      totals: {
        label: "total",
        endpoints: totalEndpoints,
        sinks: totalSinks,
        userSinks: totalUserSinks,
        secrets: totalSecrets,
        signatures: totalSignatures,
        total: totalEndpoints + totalSinks + totalUserSinks + totalSecrets + totalSignatures,
      },
    };
  }

  private buildEndpointClusters(): EndpointCluster[] {
    const clusters = new Map<string, EndpointCluster>();
    for (const asset of this.assets) {
      for (const endpoint of asset.analysis.endpoints) {
        const basePath = this.getBasePath(endpoint.label);
        const authHint = endpoint.meta && endpoint.meta.auth ? endpoint.meta.auth : "none";
        const key = `${basePath}::${authHint}`;
        if (!clusters.has(key)) {
          clusters.set(key, {
            basePath,
            authHint,
            endpoints: [],
          });
        }
        clusters.get(key)!.endpoints.push(endpoint);
      }
    }
    return Array.from(clusters.values()).sort((a, b) => {
      const pathCompare = a.basePath.localeCompare(b.basePath);
      if (pathCompare !== 0) {
        return pathCompare;
      }
      return a.authHint.localeCompare(b.authHint);
    });
  }

  private getBasePath(label: string): string {
    let pathPart = label;
    try {
      if (label.startsWith("http://") || label.startsWith("https://")) {
        pathPart = new URL(label).pathname;
      }
    } catch {
      pathPart = label;
    }
    const sanitized = pathPart.split("?")[0].split("#")[0];
    const segments = sanitized.split("/").filter(Boolean);
    if (segments.length === 0) {
      return "/";
    }
    return "/" + segments.slice(0, Math.min(2, segments.length)).join("/");
  }

  private buildTriage(coverage: CoverageSummary): TriageEntry[] {
    const triage: TriageEntry[] = [];
    for (const entry of coverage.coverage) {
      if (entry.total === 0) {
        continue;
      }
      let score = entry.endpoints + entry.sinks * 2 + entry.userSinks * 5 + entry.secrets * 6 + entry.signatures;
      const reasons: string[] = [];
      if (entry.secrets > 0) {
        reasons.push("secrets");
      }
      if (entry.userSinks > 0) {
        reasons.push("user-controlled sinks");
      }
      if (entry.sinks > 0) {
        reasons.push("sinks");
      }
      if (entry.endpoints > 0) {
        reasons.push("endpoints");
      }
      if (entry.signatures > 0) {
        reasons.push("signature matches");
      }
      if (entry.secrets > 0 && entry.userSinks > 0) {
        score += 10;
        reasons.push("secret + user sink");
      }
      if (entry.userSinks > 0 && entry.endpoints > 0) {
        score += 5;
        reasons.push("user sink + endpoint");
      }

      let severity: "low" | "medium" | "high" | "critical" = "low";
      if (score >= 25) {
        severity = "critical";
      } else if (score >= 15) {
        severity = "high";
      } else if (score >= 8) {
        severity = "medium";
      }

      triage.push({
        url: entry.label,
        filePath: this.findAssetPath(entry.label),
        score,
        severity,
        reasons,
      });
    }
    triage.sort((a, b) => b.score - a.score);
    return triage;
  }

  private buildAlerts(drift: DriftEntry[]): AlertEntry[] {
    const alerts: AlertEntry[] = [];
    for (const entry of drift) {
      const details: string[] = [];
      const added = entry.added;
      const hasSecrets = added.secrets.length > 0;
      const hasUserSinks = added.userSinks.length > 0;
      const hasSinks = added.sinks.length > 0;
      const hasEndpoints = added.endpoints.length > 0;

      if (hasSecrets) {
        details.push(`New secrets: ${added.secrets.length}`);
      }
      if (hasUserSinks) {
        details.push(`New user sinks: ${added.userSinks.length}`);
      }
      if (hasSinks) {
        details.push(`New sinks: ${added.sinks.length}`);
      }
      if (hasEndpoints) {
        details.push(`New endpoints: ${added.endpoints.length}`);
      }

      if (details.length === 0) {
        continue;
      }

      let severity: "low" | "medium" | "high" | "critical" = "low";
      if (hasSecrets && hasUserSinks) {
        severity = "critical";
      } else if (hasSecrets || hasUserSinks) {
        severity = "high";
      } else if (hasSinks && hasEndpoints) {
        severity = "medium";
      }

      alerts.push({
        url: entry.url,
        severity,
        summary: `New findings for ${entry.url}`,
        details,
      });
    }
    alerts.sort((a, b) => a.severity.localeCompare(b.severity));
    return alerts;
  }

  private findAssetPath(url: string): string {
    for (const asset of this.assets) {
      if (asset.asset.url === url) {
        return asset.analysisPath;
      }
    }
    return url;
  }
}
