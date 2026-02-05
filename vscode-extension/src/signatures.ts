import * as fs from "fs";
import * as path from "path";
import { SignatureRule } from "./types";

const DEFAULT_SIGNATURES: SignatureRule[] = [
  {
    id: "aws-access-key",
    kind: "secret",
    label: "AWS Access Key",
    pattern: "(?:^|[^A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])",
    flags: "",
  },
  {
    id: "stripe-secret",
    kind: "secret",
    label: "Stripe Secret Key",
    pattern: "(?:^|[^A-Za-z0-9])sk_live_[0-9a-zA-Z]{24,}(?![A-Za-z0-9])",
    flags: "",
  },
  {
    id: "github-token",
    kind: "secret",
    label: "GitHub Token",
    pattern: "(?:^|[^A-Za-z0-9])ghp_[0-9A-Za-z]{36}(?![A-Za-z0-9])",
    flags: "",
  },
  {
    id: "firebase-api-key",
    kind: "secret",
    label: "Firebase API Key",
    pattern: "(?:^|[^0-9A-Za-z_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])",
    flags: "",
  },
  {
    id: "graphql-endpoint",
    kind: "endpoint",
    label: "GraphQL Endpoint",
    pattern: "(?:^|[/?#])graphql(?:[/?#]|$)",
    flags: "i",
  },
  {
    id: "webhook-url",
    kind: "endpoint",
    label: "Webhook URL",
    pattern: "(?:^|[^a-z0-9])webhooks?(?:$|[^a-z0-9])",
    flags: "i",
  },
];

function normalizeRules(rules: SignatureRule[]): SignatureRule[] {
  return rules.filter((rule) => rule && rule.id && rule.pattern);
}

export async function loadSignatureRules(
  baseDir: string,
  overridePath: string | undefined,
  log: (message: string, error?: unknown) => void
): Promise<SignatureRule[]> {
  const candidates: string[] = [];
  if (overridePath) {
    candidates.push(overridePath);
  } else {
    candidates.push(path.join(baseDir, "signatures.json"));
  }

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }
    if (!fs.existsSync(candidate)) {
      continue;
    }
    try {
      const raw = await fs.promises.readFile(candidate, "utf8");
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return normalizeRules(parsed);
      }
      if (parsed && Array.isArray(parsed.rules)) {
        return normalizeRules(parsed.rules);
      }
    } catch (error) {
      log(`Failed to read signature rules at ${candidate}`, error);
      return DEFAULT_SIGNATURES;
    }
  }

  return DEFAULT_SIGNATURES;
}
