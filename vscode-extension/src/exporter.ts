import * as fs from "fs";
import * as path from "path";
import { StoreSnapshot, Finding } from "./types";
import { ensureDir } from "./utils";

function flattenFindings(snapshot: StoreSnapshot): Array<{
  category: string;
  label: string;
  detail?: string;
  filePath: string;
  line?: number;
  column?: number;
}> {
  const rows: Array<{
    category: string;
    label: string;
    detail?: string;
    filePath: string;
    line?: number;
    column?: number;
  }> = [];

  const pushFindings = (category: string, findings: Finding[]) => {
    for (const finding of findings) {
      rows.push({
        category,
        label: finding.label,
        detail: finding.detail,
        filePath: finding.filePath,
        line: finding.location?.line,
        column: finding.location?.column,
      });
    }
  };

  pushFindings("endpoint", snapshot.endpoints);
  pushFindings("sink", snapshot.sinks);
  pushFindings("user_sink", snapshot.userSinks);
  pushFindings("secret", snapshot.secrets);
  pushFindings("framework", snapshot.frameworks);
  pushFindings("signature", snapshot.signatures);
  return rows;
}

function csvEscape(value: string | number | undefined): string {
  if (value === undefined || value === null) {
    return "";
  }
  const raw = String(value);
  if (raw.includes(",") || raw.includes("\"") || raw.includes("\n")) {
    return `"${raw.replace(/\"/g, "\"\"")}"`;
  }
  return raw;
}

function buildSarif(snapshot: StoreSnapshot) {
  const rows = flattenFindings(snapshot);
  const rules: Record<string, { id: string; name: string }> = {};
  for (const row of rows) {
    if (!rules[row.category]) {
      rules[row.category] = { id: row.category, name: row.category };
    }
  }

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "JSReconduit",
            rules: Object.values(rules).map((rule) => ({
              id: rule.id,
              name: rule.name,
              shortDescription: { text: rule.name },
            })),
          },
        },
        results: rows.map((row) => ({
          ruleId: row.category,
          message: { text: row.label },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: row.filePath },
                region: {
                  startLine: row.line || 1,
                  startColumn: row.column || 1,
                },
              },
            },
          ],
        })),
      },
    ],
  };
}

export async function exportFindings(
  baseDir: string,
  snapshot: StoreSnapshot,
  format: "json" | "csv" | "sarif",
  overrideDir?: string
): Promise<string> {
  const exportDir = overrideDir && overrideDir.length > 0 ? overrideDir : path.join(baseDir, "exports");
  await ensureDir(exportDir);
  const filePath = path.join(exportDir, `findings.${format === "sarif" ? "sarif" : format}`);

  if (format === "json") {
    const payload = {
      generatedAt: new Date().toISOString(),
      findings: {
        endpoints: snapshot.endpoints,
        sinks: snapshot.sinks,
        userSinks: snapshot.userSinks,
        secrets: snapshot.secrets,
        frameworks: snapshot.frameworks,
        signatures: snapshot.signatures,
      },
      routes: snapshot.routes.map((route) => ({
        route: route.route,
        assets: route.assets.map((asset) => asset.asset.url),
      })),
      drift: snapshot.drift,
      alerts: snapshot.alerts,
      triage: snapshot.triage,
      coverage: snapshot.coverage,
    };
    await fs.promises.writeFile(filePath, JSON.stringify(payload, null, 2), "utf8");
    return filePath;
  }

  if (format === "csv") {
    const rows = flattenFindings(snapshot);
    const header = ["category", "label", "detail", "filePath", "line", "column"];
    const lines = [header.join(",")];
    for (const row of rows) {
      const fields = [
        csvEscape(row.category),
        csvEscape(row.label),
        csvEscape(row.detail),
        csvEscape(row.filePath),
        csvEscape(row.line),
        csvEscape(row.column),
      ];
      lines.push(fields.join(","));
    }
    await fs.promises.writeFile(filePath, lines.join("\n") + "\n", "utf8");
    return filePath;
  }

  const sarif = buildSarif(snapshot);
  await fs.promises.writeFile(filePath, JSON.stringify(sarif, null, 2), "utf8");
  return filePath;
}
