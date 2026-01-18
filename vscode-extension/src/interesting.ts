import * as fs from "fs";
import * as path from "path";
import { Finding, StoreSnapshot } from "./types";
import { ensureDir } from "./utils";

function unique(values: string[]): string[] {
  return Array.from(new Set(values)).sort();
}

function serializeFindings(findings: Finding[]): object[] {
  return findings.map((finding) => ({
    kind: finding.kind,
    label: finding.label,
    detail: finding.detail,
    filePath: finding.filePath,
    location: finding.location,
    meta: finding.meta,
  }));
}

function secretValue(finding: Finding): string {
  if (finding.detail && finding.detail.length > 0) {
    return finding.detail;
  }
  return finding.label;
}

async function writeTextList(filePath: string, values: string[]): Promise<void> {
  await ensureDir(path.dirname(filePath));
  await fs.promises.writeFile(filePath, values.join("\n") + "\n", "utf8");
}

async function writeJson(filePath: string, data: object): Promise<void> {
  await ensureDir(path.dirname(filePath));
  await fs.promises.writeFile(filePath, JSON.stringify(data, null, 2), "utf8");
}

export async function writeInterestingOutputs(baseDir: string, snapshot: StoreSnapshot): Promise<void> {
  const interestingDir = path.join(baseDir, "interesting");
  const apiDir = path.join(interestingDir, "apis");
  const secretsDir = path.join(interestingDir, "secrets");
  const sinksDir = path.join(interestingDir, "sinks");
  const routesDir = path.join(interestingDir, "routes");
  const driftDir = path.join(interestingDir, "drift");
  const sourcemapDir = path.join(interestingDir, "sourcemaps");
  const triageDir = path.join(interestingDir, "triage");
  const alertsDir = path.join(interestingDir, "alerts");
  const coverageDir = path.join(interestingDir, "coverage");
  const signaturesDir = path.join(interestingDir, "signatures");
  const clusterDir = path.join(interestingDir, "clusters");
  const flowDir = path.join(interestingDir, "flows");

  const endpoints = unique(snapshot.endpoints.map((finding) => finding.label));
  const secrets = unique(snapshot.secrets.map((finding) => secretValue(finding)));
  const sinks = unique(snapshot.sinks.map((finding) => finding.label));
  const userSinks = unique(snapshot.userSinks.map((finding) => finding.label));
  const routes = snapshot.routes.map((entry) => entry.route);
  const driftUrls = snapshot.drift.map((entry) => entry.url);
  const alerts = snapshot.alerts.map((entry) => `${entry.severity}: ${entry.summary}`);
  const triage = snapshot.triage.map((entry) => `${entry.severity} (${entry.score}) ${entry.url}`);
  const signatures = unique(snapshot.signatures.map((finding) => finding.label));
  const clusters = snapshot.clusters.map(
    (cluster) => `${cluster.basePath}\t${cluster.authHint}\t${cluster.endpoints.length}`
  );

  await Promise.all([
    writeTextList(path.join(apiDir, "endpoints.txt"), endpoints),
    writeJson(path.join(apiDir, "endpoints.json"), serializeFindings(snapshot.endpoints)),
    writeTextList(path.join(secretsDir, "secrets.txt"), secrets),
    writeJson(path.join(secretsDir, "secrets.json"), serializeFindings(snapshot.secrets)),
    writeTextList(path.join(sinksDir, "sinks.txt"), sinks),
    writeTextList(path.join(sinksDir, "user-sinks.txt"), userSinks),
    writeJson(path.join(sinksDir, "user-sinks.json"), serializeFindings(snapshot.userSinks)),
    writeTextList(path.join(signaturesDir, "signatures.txt"), signatures),
    writeJson(path.join(signaturesDir, "signatures.json"), serializeFindings(snapshot.signatures)),
    writeTextList(path.join(routesDir, "routes.txt"), routes),
    writeJson(
      path.join(routesDir, "routes.json"),
      snapshot.routes.map((route) => ({
        route: route.route,
        assets: route.assets.map((asset) => ({
          url: asset.asset.url,
          path: asset.analysisPath,
        })),
      }))
    ),
    writeTextList(path.join(driftDir, "drift.txt"), driftUrls),
    writeJson(
      path.join(driftDir, "drift.json"),
      snapshot.drift.map((entry) => ({
        url: entry.url,
        fromTimestamp: entry.fromTimestamp,
        toTimestamp: entry.toTimestamp,
        added: {
          endpoints: serializeFindings(entry.added.endpoints),
          sinks: serializeFindings(entry.added.sinks),
          userSinks: serializeFindings(entry.added.userSinks),
          secrets: serializeFindings(entry.added.secrets),
          paths: serializeFindings(entry.added.paths),
          urls: serializeFindings(entry.added.urls),
        },
      }))
    ),
    writeJson(path.join(sourcemapDir, "sourcemap-graph.json"), snapshot.sourcemapGraph),
    writeTextList(path.join(triageDir, "triage.txt"), triage),
    writeJson(path.join(triageDir, "triage.json"), snapshot.triage),
    writeTextList(path.join(alertsDir, "alerts.txt"), alerts),
    writeJson(path.join(alertsDir, "alerts.json"), snapshot.alerts),
    writeJson(path.join(coverageDir, "coverage.json"), snapshot.coverage),
    writeTextList(
      path.join(coverageDir, "coverage.txt"),
      snapshot.coverage.coverage.map(
        (entry) =>
          `${entry.total}\tE:${entry.endpoints}\tS:${entry.sinks}\tU:${entry.userSinks}\tK:${entry.secrets}\tG:${entry.signatures}\t${entry.label}`
      )
    ),
    writeTextList(path.join(clusterDir, "clusters.txt"), clusters),
    writeJson(path.join(clusterDir, "clusters.json"), snapshot.clusters),
    writeJson(path.join(flowDir, "call-graph.json"), snapshot.callGraph),
    writeJson(path.join(flowDir, "traces.json"), snapshot.traces),
  ]);

  const summary = {
    endpoints: endpoints.length,
    secrets: secrets.length,
    sinks: sinks.length,
    userSinks: userSinks.length,
    routes: routes.length,
    drift: driftUrls.length,
    sourcemaps: snapshot.sourcemapGraph.length,
    alerts: snapshot.alerts.length,
    triage: snapshot.triage.length,
    coverage: snapshot.coverage.coverage.length,
    signatures: signatures.length,
    clusters: snapshot.clusters.length,
    traces: snapshot.traces.length,
    callGraph: snapshot.callGraph.length,
    updatedAt: new Date().toISOString(),
  };
  await writeJson(path.join(interestingDir, "summary.json"), summary);
}
