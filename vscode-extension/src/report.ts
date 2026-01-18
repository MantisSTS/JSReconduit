import * as fs from "fs";
import * as path from "path";
import { StoreSnapshot } from "./types";
import { ensureDir } from "./utils";

function bulletList(items: string[]): string {
  if (items.length === 0) {
    return "- (none)\n";
  }
  return items.map((item) => `- ${item}`).join("\n") + "\n";
}

export async function writeReport(
  baseDir: string,
  snapshot: StoreSnapshot,
  overrideDir?: string
): Promise<string> {
  const reportDir = overrideDir && overrideDir.length > 0 ? overrideDir : path.join(baseDir, "reports");
  await ensureDir(reportDir);
  const reportPath = path.join(reportDir, "jsreconduit-report.md");

  const totals = snapshot.coverage.totals;
  const triage = snapshot.triage.slice(0, 10);
  const secrets = snapshot.secrets.slice(0, 10).map((finding) => finding.label);
  const endpoints = snapshot.endpoints.slice(0, 10).map((finding) => finding.label);
  const sinks = snapshot.userSinks.slice(0, 10).map((finding) => finding.label);
  const alerts = snapshot.alerts.slice(0, 10).map((alert) => `${alert.severity}: ${alert.summary}`);

  const report = `# JSReconduit Report

Generated: ${new Date().toISOString()}

## Summary

- Assets analyzed: ${snapshot.assets.length}
- Routes mapped: ${snapshot.routes.length}
- Endpoints: ${totals.endpoints}
- Sinks: ${totals.sinks}
- User-controlled sinks: ${totals.userSinks}
- Secrets: ${totals.secrets}
- Signature matches: ${totals.signatures}
- Drift entries: ${snapshot.drift.length}
- Alerts: ${snapshot.alerts.length}

## Top Triage

${bulletList(
  triage.map((entry) => `${entry.severity} (${entry.score}) ${entry.url} (${entry.filePath})`)
)}

## Top Secrets

${bulletList(secrets)}

## Top Endpoints

${bulletList(endpoints)}

## User-Controlled Sinks

${bulletList(sinks)}

## Alerts

${bulletList(alerts)}
`;

  await fs.promises.writeFile(reportPath, report, "utf8");
  return reportPath;
}
