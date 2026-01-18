import * as fs from "fs";
import * as path from "path";
import { SignatureRule } from "./types";

const DEFAULT_SIGNATURES: SignatureRule[] = [
  {
    id: "aws-access-key",
    kind: "secret",
    label: "AWS Access Key",
    pattern: "AKIA[0-9A-Z]{16}",
  },
  {
    id: "stripe-secret",
    kind: "secret",
    label: "Stripe Secret Key",
    pattern: "sk_live_[0-9a-zA-Z]{16,}",
  },
  {
    id: "github-token",
    kind: "secret",
    label: "GitHub Token",
    pattern: "ghp_[0-9A-Za-z]{20,}",
  },
  {
    id: "firebase-api-key",
    kind: "secret",
    label: "Firebase API Key",
    pattern: "AIza[0-9A-Za-z\\-_]{20,}",
  },
  {
    id: "graphql-endpoint",
    kind: "endpoint",
    label: "GraphQL Endpoint",
    pattern: "/graphql",
    flags: "i",
  },
  {
    id: "webhook-url",
    kind: "endpoint",
    label: "Webhook URL",
    pattern: "webhook",
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

