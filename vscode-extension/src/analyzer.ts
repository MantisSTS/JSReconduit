import * as acorn from "acorn";
import * as walk from "acorn-walk";
import { AnalysisResult, CallGraphEdge, Finding, FlowEndpoint, FlowTrace, SignatureRule } from "./types";
import {
  extractQueryParams,
  isLikelyPath,
  isLikelyUrl,
  isWordCandidate,
  splitPathSegments,
  toLocation,
} from "./utils";

function addWord(set: Set<string>, value?: string): void {
  if (!value) {
    return;
  }
  if (isWordCandidate(value)) {
    set.add(value);
  }
}

function addWordsFromPath(set: Set<string>, value: string): void {
  for (const segment of splitPathSegments(value)) {
    addWord(set, segment);
  }
}

function buildFinding(
  kind: Finding["kind"],
  label: string,
  filePath: string,
  node?: any,
  detail?: string,
  meta?: Record<string, string>
): Finding {
  return {
    kind,
    label,
    detail,
    filePath,
    location: toLocation(node),
    meta,
  };
}

const USER_IDENTIFIERS = new Set([
  "location",
  "hash",
  "search",
  "query",
  "params",
  "param",
  "input",
  "user",
  "url",
  "uri",
  "href",
  "ref",
  "message",
  "data",
  "payload",
  "event",
]);

const USER_MEMBER_PATHS = new Set([
  "location",
  "location.href",
  "location.search",
  "location.hash",
  "location.pathname",
  "location.origin",
  "location.host",
  "location.hostname",
  "location.port",
  "location.protocol",
  "window.location",
  "window.location.href",
  "window.location.search",
  "window.location.hash",
  "window.location.pathname",
  "window.location.origin",
  "window.location.host",
  "window.location.hostname",
  "window.location.port",
  "window.location.protocol",
  "window.name",
  "document.location",
  "document.URL",
  "document.documentURI",
  "document.baseURI",
  "document.cookie",
  "document.referrer",
  "event.data",
  "message.data",
  "history.state",
]);

const SOURCE_MEMBER_PATHS = new Set(USER_MEMBER_PATHS);
const SOURCE_CALL_PATHS = new Set(["localStorage.getItem", "sessionStorage.getItem"]);
const SOURCE_CALL_NAMES = new Set(["URLSearchParams"]);

const SINK_CALLS = new Set(["eval", "Function", "setTimeout", "setInterval"]);
const SINK_METHODS = new Set([
  "postMessage",
  "write",
  "writeln",
  "insertAdjacentHTML",
  "append",
  "prepend",
  "replaceWith",
  "after",
  "before",
  "open",
  "setAttribute",
]);
const SINK_ASSIGNMENTS = new Set([
  "innerHTML",
  "outerHTML",
  "srcdoc",
  "href",
  "src",
  "action",
  "formAction",
]);

const DOM_INSERT_METHODS = new Set(["append", "prepend", "replaceWith", "after", "before", "insertAdjacentHTML"]);

const SECRET_PREFIXES = ["AKIA", "AIza", "ghp_", "sk_", "pk_", "xoxb-", "xoxp-"];
const SECRET_KEYWORDS = ["secret", "token", "apikey", "api_key", "api-key", "password", "passwd", "auth", "bearer"];
const HTTP_VERBS = new Set(["get", "post", "put", "patch", "delete", "options", "head"]);
const FEATURE_KEYWORDS = [
  "feature",
  "flag",
  "toggle",
  "experiment",
  "variant",
  "rollout",
  "abtest",
  "ab_test",
  "switch",
];
const FEATURE_CONTAINER_KEYS = new Set([
  "featureflags",
  "feature_flags",
  "feature-toggles",
  "flags",
  "toggles",
  "experiments",
  "variants",
  "rollouts",
]);

function truncateValue(value: string, max = 120): string {
  if (value.length <= max) {
    return value;
  }
  return value.slice(0, max) + "...";
}

function getStringLiteral(node: any): string | null {
  if (!node) {
    return null;
  }
  if (node.type === "Literal" && typeof node.value === "string") {
    return node.value;
  }
  if (node.type === "Identifier") {
    return node.name;
  }
  return null;
}

function getStaticString(node: any): string | null {
  if (!node) {
    return null;
  }
  if (node.type === "Literal" && typeof node.value === "string") {
    return node.value;
  }
  if (node.type === "TemplateLiteral" && Array.isArray(node.expressions) && node.expressions.length === 0) {
    const quasi = node.quasis && node.quasis[0];
    if (quasi && quasi.value && typeof quasi.value.raw === "string") {
      return quasi.value.raw;
    }
  }
  return null;
}

function extractEndpointString(node: any): string | null {
  const direct = getStaticString(node);
  if (direct) {
    return direct;
  }
  if (node && node.type === "NewExpression") {
    const callee = node.callee;
    if (callee && callee.type === "Identifier" && callee.name === "Request") {
      return getStaticString(node.arguments && node.arguments[0]);
    }
  }
  return null;
}

function hasHtmlLikeString(args: any[]): boolean {
  for (const arg of args) {
    if (!arg) {
      continue;
    }
    if (arg.type === "Literal" && typeof arg.value === "string") {
      if (arg.value.indexOf("<") !== -1 || arg.value.indexOf(">") !== -1) {
        return true;
      }
    }
    if (arg.type === "TemplateLiteral" && arg.quasis) {
      for (const quasi of arg.quasis) {
        const raw = quasi.value && quasi.value.raw;
        if (raw && (raw.indexOf("<") !== -1 || raw.indexOf(">") !== -1)) {
          return true;
        }
      }
    }
  }
  return false;
}

function buildSignatureFindings(
  value: string,
  filePath: string,
  node: any,
  rules: SignatureRule[]
): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rules) {
    let regex: RegExp | null = null;
    try {
      regex = new RegExp(rule.pattern, rule.flags || "i");
    } catch {
      continue;
    }
    if (!regex.test(value)) {
      continue;
    }
    const kind = rule.kind || "signature";
    const label = rule.label ? rule.label : rule.id;
    findings.push(buildFinding(kind, label, filePath, node, truncateValue(value)));
  }
  return findings;
}

function shannonEntropy(value: string): number {
  const counts: Record<string, number> = {};
  for (const ch of value) {
    counts[ch] = (counts[ch] || 0) + 1;
  }
  let entropy = 0;
  const length = value.length;
  for (const key in counts) {
    const p = counts[key] / length;
    entropy -= p * Math.log(p) / Math.LN2;
  }
  return entropy;
}

function isBase64ish(value: string): boolean {
  if (value.length < 20) {
    return false;
  }
  for (const ch of value) {
    if (
      (ch >= "A" && ch <= "Z") ||
      (ch >= "a" && ch <= "z") ||
      (ch >= "0" && ch <= "9") ||
      ch === "+" ||
      ch === "/" ||
      ch === "=" ||
      ch === "-" ||
      ch === "_"
    ) {
      continue;
    }
    return false;
  }
  return true;
}

function isHexish(value: string): boolean {
  if (value.length < 20) {
    return false;
  }
  for (const ch of value) {
    if (
      (ch >= "0" && ch <= "9") ||
      (ch >= "a" && ch <= "f") ||
      (ch >= "A" && ch <= "F")
    ) {
      continue;
    }
    return false;
  }
  return true;
}

function isLikelyHostname(value: string): boolean {
  if (!value || value.length < 3 || value.length > 255) {
    return false;
  }
  if (value.includes("/") || value.includes("://") || value.includes("@")) {
    return false;
  }
  const stripped = value.split(":")[0];
  if (!/^[A-Za-z0-9.-]+$/.test(stripped)) {
    return false;
  }
  if (stripped.startsWith(".") || stripped.endsWith(".")) {
    return false;
  }
  const parts = stripped.split(".");
  if (parts.length < 2) {
    return false;
  }
  return parts.every((part) => part.length > 0 && part.length <= 63);
}

function extractExtension(value: string): string | null {
  if (!value || value.length < 3) {
    return null;
  }
  const cleaned = value.split("?")[0].split("#")[0];
  const last = cleaned.split("/").pop() || "";
  const match = last.match(/\\.([A-Za-z0-9]{1,8})$/);
  if (!match) {
    return null;
  }
  return `.${match[1]}`;
}

function isMimeType(value: string): boolean {
  if (!value || value.length > 80 || value.indexOf("/") === -1) {
    return false;
  }
  if (value.startsWith("./") || value.startsWith("../") || value.startsWith("/")) {
    return false;
  }
  return /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/i.test(value);
}

function detectGraphQL(value: string): { type: string; label: string } | null {
  const normalized = value.replace(/\\s+/g, " ").trim().toLowerCase();
  if (normalized.startsWith("query") || normalized.includes(" query ")) {
    return { type: "query", label: "graphql:query" };
  }
  if (normalized.startsWith("mutation") || normalized.includes(" mutation ")) {
    return { type: "mutation", label: "graphql:mutation" };
  }
  if (normalized.startsWith("subscription") || normalized.includes(" subscription ")) {
    return { type: "subscription", label: "graphql:subscription" };
  }
  if (normalized.includes("{") && normalized.includes("}") && normalized.includes("__typename")) {
    return { type: "graphql", label: "graphql:fragment" };
  }
  return null;
}

function looksLikeData(value: string): boolean {
  if (!value || value.length < 4 || value.length > 80) {
    return false;
  }
  if (looksLikeCssSelector(value)) {
    return false;
  }
  if (!/^[A-Za-z0-9 _:.\\-]+$/.test(value)) {
    return false;
  }
  if (!/[A-Za-z]/.test(value)) {
    return false;
  }
  return true;
}

function looksLikeCssSelector(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) {
    return false;
  }
  if (
    trimmed.startsWith(".") ||
    trimmed.startsWith("#") ||
    trimmed.startsWith("[") ||
    trimmed.startsWith(":")
  ) {
    return true;
  }
  if (/\[[^\]]+\]/.test(trimmed)) {
    return true;
  }
  if (/:([A-Za-z][A-Za-z0-9_-]*)/.test(trimmed)) {
    return true;
  }
  if (/[.#][A-Za-z][A-Za-z0-9_-]*/.test(trimmed)) {
    return true;
  }
  return false;
}

function looksLikeSchema(node: any): boolean {
  if (!node || node.type !== "ObjectExpression" || !node.properties) {
    return false;
  }
  let hasType = false;
  let hasProps = false;
  let hasRequired = false;
  for (const prop of node.properties) {
    const keyName = getStringLiteral(prop && prop.key);
    if (!keyName) {
      continue;
    }
    const lower = keyName.toLowerCase();
    if (lower === "type" && prop.value && prop.value.type === "Literal" && prop.value.value === "object") {
      hasType = true;
    }
    if (lower === "properties") {
      hasProps = true;
    }
    if (lower === "required") {
      hasRequired = true;
    }
  }
  return (hasType && hasProps) || (hasProps && hasRequired);
}

function isJwt(value: string): boolean {
  if (value.length < 20) {
    return false;
  }
  const parts = value.split(".");
  if (parts.length !== 3) {
    return false;
  }
  for (const part of parts) {
    if (part.length < 6) {
      return false;
    }
    if (!/^[A-Za-z0-9_-]+$/.test(part)) {
      return false;
    }
  }
  return true;
}

function isUuid(value: string): boolean {
  return /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/.test(
    value
  );
}

function isLikelySecret(value: string): { isSecret: boolean; reason: string } {
  if (value.length < 20) {
    return { isSecret: false, reason: "" };
  }
  for (const prefix of SECRET_PREFIXES) {
    if (value.startsWith(prefix)) {
      return { isSecret: true, reason: "known-prefix" };
    }
  }
  if (isJwt(value)) {
    return { isSecret: true, reason: "jwt" };
  }
  if (isUuid(value)) {
    return { isSecret: false, reason: "uuid" };
  }
  if (/\\s/.test(value)) {
    return { isSecret: false, reason: "" };
  }
  if (/[<>{}\\[\\]]/.test(value)) {
    return { isSecret: false, reason: "" };
  }
  const base64ish = isBase64ish(value);
  const hexish = isHexish(value);
  if ((isLikelyUrl(value) || isLikelyPath(value)) && !base64ish && !hexish) {
    return { isSecret: false, reason: "" };
  }
  if (isLikelyHostname(value) && !base64ish && !hexish) {
    return { isSecret: false, reason: "" };
  }
  if (extractExtension(value) && !base64ish && !hexish) {
    return { isSecret: false, reason: "" };
  }
  const entropy = shannonEntropy(value);
  if (base64ish || hexish) {
    if (entropy >= 3.6 && value.length >= 24) {
      return { isSecret: true, reason: "high-entropy" };
    }
    return { isSecret: false, reason: "" };
  }
  if (entropy >= 4.0 && value.length > 40 && /^[A-Za-z0-9._$-]+$/.test(value)) {
    return { isSecret: true, reason: "high-entropy" };
  }
  return { isSecret: false, reason: "" };
}

function looksLikeSecretName(name: string): boolean {
  if (!name) {
    return false;
  }
  const lower = name.toLowerCase();
  return SECRET_KEYWORDS.some((keyword) => lower.includes(keyword));
}

function looksSensitiveLiteral(value: string): boolean {
  if (!value || value.length < 12) {
    return false;
  }
  if (/\\s/.test(value)) {
    return false;
  }
  if (/[<>{}\\[\\]]/.test(value)) {
    return false;
  }
  if (isLikelyUrl(value) || isLikelyPath(value) || isLikelyHostname(value) || isMimeType(value)) {
    return false;
  }
  if (extractExtension(value)) {
    return false;
  }
  if (!/^[A-Za-z0-9._+$\\-\\/=?]+$/.test(value)) {
    return false;
  }
  return true;
}

function getMemberPath(node: any): string | null {
  const parts: string[] = [];
  let current = node;
  while (current && current.type === "MemberExpression") {
    const prop = current.property;
    if (prop) {
      if (prop.type === "Identifier") {
        parts.unshift(prop.name);
      } else if (prop.type === "Literal" && typeof prop.value === "string") {
        parts.unshift(prop.value);
      }
    }
    current = current.object;
  }
  if (current && current.type === "Identifier") {
    parts.unshift(current.name);
  }
  if (!parts.length) {
    return null;
  }
  return parts.join(".");
}

function isUserControlled(node: any): boolean {
  if (!node) {
    return false;
  }
  switch (node.type) {
    case "Identifier":
      return USER_IDENTIFIERS.has(node.name);
    case "MemberExpression": {
      const path = getMemberPath(node);
      if (path && USER_MEMBER_PATHS.has(path)) {
        return true;
      }
      return isUserControlled(node.object);
    }
    case "CallExpression": {
      const callee = node.callee;
      if (callee && callee.type === "MemberExpression") {
        const path = getMemberPath(callee);
        if (path && (path === "localStorage.getItem" || path === "sessionStorage.getItem")) {
          return true;
        }
        if (path && (path.endsWith(".get") || path.endsWith(".getAll"))) {
          if (path.includes("searchParams") || path.includes("params") || path.includes("URLSearchParams")) {
            return true;
          }
        }
      }
      if (callee && callee.type === "Identifier" && callee.name === "URLSearchParams") {
        return true;
      }
      if (node.arguments) {
        return node.arguments.some((arg: any) => isUserControlled(arg));
      }
      return false;
    }
    case "NewExpression":
      return node.arguments ? node.arguments.some((arg: any) => isUserControlled(arg)) : false;
    case "BinaryExpression":
    case "LogicalExpression":
      return isUserControlled(node.left) || isUserControlled(node.right);
    case "ConditionalExpression":
      return isUserControlled(node.test) || isUserControlled(node.consequent) || isUserControlled(node.alternate);
    case "UnaryExpression":
      return isUserControlled(node.argument);
    case "UpdateExpression":
      return isUserControlled(node.argument);
    case "SequenceExpression":
      return node.expressions ? node.expressions.some((expr: any) => isUserControlled(expr)) : false;
    case "TemplateLiteral":
      return node.expressions ? node.expressions.some((expr: any) => isUserControlled(expr)) : false;
    case "AssignmentExpression":
      return isUserControlled(node.right);
    case "ArrayExpression":
      return node.elements ? node.elements.some((elem: any) => isUserControlled(elem)) : false;
    case "ObjectExpression":
      return node.properties
        ? node.properties.some((prop: any) => prop && prop.value && isUserControlled(prop.value))
        : false;
    default:
      return false;
  }
}

function hasUserControlledHtml(node: any): boolean {
  if (!node) {
    return false;
  }
  if (isUserControlled(node)) {
    return true;
  }
  if (node.type === "ObjectExpression" && node.properties) {
    for (const prop of node.properties) {
      const keyName = getStringLiteral(prop && prop.key);
      if (keyName === "__html" && isUserControlled(prop.value)) {
        return true;
      }
    }
  }
  return false;
}

const AUTH_HEADER_KEYS = [
  "authorization",
  "x-api-key",
  "api-key",
  "x-auth-token",
  "x-csrf-token",
  "x-xsrf-token",
  "x-forwarded-user",
  "cookie",
];

function extractAuthHintFromHeaders(node: any): string | null {
  if (!node || node.type !== "ObjectExpression" || !node.properties) {
    return null;
  }
  for (const prop of node.properties) {
    const keyName = getStringLiteral(prop && prop.key);
    if (!keyName) {
      continue;
    }
    const lower = keyName.toLowerCase();
    if (AUTH_HEADER_KEYS.includes(lower)) {
      return keyName;
    }
  }
  return null;
}

function extractAuthHintFromOptions(node: any): string | null {
  if (!node || node.type !== "ObjectExpression" || !node.properties) {
    return null;
  }
  for (const prop of node.properties) {
    const keyName = getStringLiteral(prop && prop.key);
    if (!keyName) {
      continue;
    }
    const lower = keyName.toLowerCase();
    if (lower === "headers") {
      const hint = extractAuthHintFromHeaders(prop.value);
      if (hint) {
        return hint;
      }
    }
    if (lower === "auth") {
      return "auth";
    }
    if (lower === "withcredentials" || lower === "credentials") {
      return "credentials";
    }
  }
  return null;
}

function extractUrlFromOptions(node: any): string | null {
  if (!node || node.type !== "ObjectExpression" || !node.properties) {
    return null;
  }
  let url: string | null = null;
  let baseUrl: string | null = null;
  let pathValue: string | null = null;
  for (const prop of node.properties) {
    const keyName = getStringLiteral(prop && prop.key);
    if (!keyName) {
      continue;
    }
    const lower = keyName.toLowerCase();
    if (lower === "url") {
      url = extractEndpointString(prop.value);
    } else if (lower === "baseurl") {
      baseUrl = extractEndpointString(prop.value);
    } else if (lower === "path") {
      pathValue = extractEndpointString(prop.value);
    }
  }
  if (url) {
    return baseUrl ? baseUrl.replace(/\/$/, "") + (url.startsWith("/") ? url : `/${url}`) : url;
  }
  if (baseUrl && pathValue) {
    return baseUrl.replace(/\/$/, "") + (pathValue.startsWith("/") ? pathValue : `/${pathValue}`);
  }
  return url || baseUrl || pathValue;
}

function extractObjectKeys(node: any): string[] {
  if (!node || node.type !== "ObjectExpression" || !node.properties) {
    return [];
  }
  const keys: string[] = [];
  for (const prop of node.properties) {
    const keyName = getStringLiteral(prop && prop.key);
    if (keyName) {
      keys.push(keyName);
    }
  }
  return keys;
}

function looksLikeFeatureFlagName(name: string): boolean {
  if (!name) {
    return false;
  }
  const lower = name.toLowerCase();
  if (FEATURE_CONTAINER_KEYS.has(lower)) {
    return false;
  }
  if (lower.length < 3 || lower.length > 80) {
    return false;
  }
  return FEATURE_KEYWORDS.some((keyword) => lower.includes(keyword)) || lower.startsWith("ff_");
}

function looksLikeFeatureFlagContainer(name: string): boolean {
  if (!name) {
    return false;
  }
  const lower = name.toLowerCase();
  return FEATURE_CONTAINER_KEYS.has(lower);
}

function looksLikeFeatureFlagPath(path: string): boolean {
  if (!path) {
    return false;
  }
  const lower = path.toLowerCase();
  if (FEATURE_KEYWORDS.some((keyword) => lower.includes(keyword))) {
    return true;
  }
  return /(?:\\.|_)ff_[a-z0-9_]+/.test(lower);
}

function isToggleLiteral(node: any): boolean {
  if (!node) {
    return false;
  }
  if (node.type === "Literal") {
    if (typeof node.value === "boolean") {
      return true;
    }
    if (typeof node.value === "number") {
      return node.value === 0 || node.value === 1;
    }
    if (typeof node.value === "string") {
      const lower = node.value.toLowerCase();
      return ["true", "false", "on", "off", "enabled", "disabled", "1", "0"].includes(lower);
    }
  }
  return false;
}

function isFunctionNode(node: any): boolean {
  return (
    node &&
    (node.type === "FunctionDeclaration" ||
      node.type === "FunctionExpression" ||
      node.type === "ArrowFunctionExpression")
  );
}

function getFunctionName(node: any, ancestors: any[]): string {
  if (node.id && node.id.name) {
    return node.id.name;
  }
  for (let i = ancestors.length - 1; i >= 0; i -= 1) {
    const parent = ancestors[i];
    if (!parent) {
      continue;
    }
    if (parent.type === "VariableDeclarator" && parent.id && parent.id.type === "Identifier") {
      return parent.id.name;
    }
    if (parent.type === "AssignmentExpression" && parent.left) {
      const left = parent.left;
      if (left.type === "Identifier") {
        return left.name;
      }
      const path = getMemberPath(left);
      if (path) {
        return path;
      }
    }
    if (parent.type === "Property") {
      const name = getStringLiteral(parent.key);
      if (name) {
        return name;
      }
    }
  }
  const loc = node.loc && node.loc.start ? `${node.loc.start.line}:${node.loc.start.column + 1}` : "unknown";
  return `anonymous@${loc}`;
}

function getParamNames(node: any): string[] {
  if (!node || !node.params) {
    return [];
  }
  const names: string[] = [];
  for (const param of node.params) {
    if (param.type === "Identifier") {
      names.push(param.name);
    } else if (param.type === "AssignmentPattern" && param.left && param.left.type === "Identifier") {
      names.push(param.left.name);
    }
  }
  return names;
}

function getCalleeName(node: any): string | null {
  if (!node) {
    return null;
  }
  if (node.type === "Identifier") {
    return node.name;
  }
  if (node.type === "MemberExpression") {
    return getMemberPath(node);
  }
  return null;
}

function getSourceEndpoint(node: any): FlowEndpoint | null {
  if (!node) {
    return null;
  }
  if (node.type === "MemberExpression") {
    const path = getMemberPath(node);
    if (path && SOURCE_MEMBER_PATHS.has(path)) {
      return { label: path, location: toLocation(node), kind: "source" };
    }
  }
  if (node.type === "CallExpression") {
    const calleePath = getCalleeName(node.callee);
    if (calleePath && SOURCE_CALL_PATHS.has(calleePath)) {
      return { label: calleePath, location: toLocation(node), kind: "source" };
    }
    if (calleePath && SOURCE_CALL_NAMES.has(calleePath)) {
      return { label: calleePath, location: toLocation(node), kind: "source" };
    }
    if (calleePath && calleePath.endsWith(".get") && calleePath.includes("searchParams")) {
      return { label: calleePath, location: toLocation(node), kind: "source" };
    }
  }
  if (node.type === "NewExpression") {
    const calleePath = getCalleeName(node.callee);
    if (calleePath && SOURCE_CALL_NAMES.has(calleePath)) {
      return { label: calleePath, location: toLocation(node), kind: "source" };
    }
  }
  return null;
}

type TaintPath = { source: FlowEndpoint; chain: string[] };

interface FunctionSummary {
  params: string[];
  paramTraces: Record<number, { sink: FlowEndpoint; path: string[] }[]>;
}

function mergeTaints(values: TaintPath[][]): TaintPath[] {
  const merged: TaintPath[] = [];
  for (const entry of values) {
    merged.push(...entry);
  }
  return merged;
}

function cloneTaints(taints: TaintPath[]): TaintPath[] {
  return taints.map((entry) => ({ source: entry.source, chain: entry.chain.slice() }));
}

function evaluateExpression(node: any, taints: Map<string, TaintPath[]>): TaintPath[] {
  if (!node) {
    return [];
  }
  const source = getSourceEndpoint(node);
  if (source) {
    return [{ source, chain: [source.label] }];
  }
  switch (node.type) {
    case "Identifier": {
      const found = taints.get(node.name);
      return found ? cloneTaints(found) : [];
    }
    case "MemberExpression": {
      const path = getMemberPath(node);
      if (path) {
        const found = taints.get(path);
        if (found) {
          return cloneTaints(found);
        }
      }
      return evaluateExpression(node.object, taints);
    }
    case "CallExpression":
      return mergeTaints(
        (node.arguments || []).map((arg: any) => evaluateExpression(arg, taints))
      );
    case "NewExpression":
      return mergeTaints(
        (node.arguments || []).map((arg: any) => evaluateExpression(arg, taints))
      );
    case "BinaryExpression":
    case "LogicalExpression":
      return mergeTaints([evaluateExpression(node.left, taints), evaluateExpression(node.right, taints)]);
    case "ConditionalExpression":
      return mergeTaints([
        evaluateExpression(node.test, taints),
        evaluateExpression(node.consequent, taints),
        evaluateExpression(node.alternate, taints),
      ]);
    case "UnaryExpression":
      return evaluateExpression(node.argument, taints);
    case "UpdateExpression":
      return evaluateExpression(node.argument, taints);
    case "SequenceExpression":
      return mergeTaints(node.expressions.map((expr: any) => evaluateExpression(expr, taints)));
    case "TemplateLiteral":
      return mergeTaints((node.expressions || []).map((expr: any) => evaluateExpression(expr, taints)));
    case "ArrayExpression":
      return mergeTaints((node.elements || []).map((elem: any) => evaluateExpression(elem, taints)));
    case "ObjectExpression":
      return mergeTaints(
        (node.properties || [])
          .map((prop: any) => (prop && prop.value ? evaluateExpression(prop.value, taints) : []))
      );
    default:
      return [];
  }
}

function getTargetName(node: any): string | null {
  if (!node) {
    return null;
  }
  if (node.type === "Identifier") {
    return node.name;
  }
  if (node.type === "MemberExpression") {
    return getMemberPath(node);
  }
  return null;
}

function recordSinkTraces(
  traces: FlowTrace[],
  filePath: string,
  sinkLabel: string,
  sinkNode: any,
  taints: TaintPath[]
): void {
  if (!taints.length) {
    return;
  }
  const sink: FlowEndpoint = { label: sinkLabel, location: toLocation(sinkNode) };
  for (const taint of taints) {
    traces.push({
      filePath,
      source: taint.source,
      sink,
      path: [...taint.chain, sinkLabel],
    });
  }
}

function analyzeTaintFlow(
  node: any,
  filePath: string,
  summaries: Map<string, FunctionSummary>,
  options?: { initialTaints?: Map<string, TaintPath[]>; skipNestedFunctions?: boolean }
): FlowTrace[] {
  const taints = options?.initialTaints ? new Map(options.initialTaints) : new Map<string, TaintPath[]>();
  const traces: FlowTrace[] = [];
  const skipNested = options?.skipNestedFunctions ?? false;

  const visitors: any = {
    VariableDeclarator(node: any, _state: any, c: any) {
      if (node.init) {
        const valueTaints = evaluateExpression(node.init, taints);
        const name = getTargetName(node.id);
        if (name && valueTaints.length > 0) {
          const updated = valueTaints.map((entry) => ({
            source: entry.source,
            chain: [...entry.chain, name],
          }));
          taints.set(name, updated);
        }
      }
      if (node.init) {
        c(node.init, _state);
      }
    },
    AssignmentExpression(node: any, _state: any, c: any) {
      if (node.right) {
        const valueTaints = evaluateExpression(node.right, taints);
        const name = getTargetName(node.left);
        if (name && valueTaints.length > 0) {
          const updated = valueTaints.map((entry) => ({
            source: entry.source,
            chain: [...entry.chain, name],
          }));
          taints.set(name, updated);
        }
        if (node.left && node.left.type === "MemberExpression") {
          const propName = node.left.property && (node.left.property.name || node.left.property.value);
          if (propName && SINK_ASSIGNMENTS.has(String(propName))) {
            recordSinkTraces(traces, filePath, String(propName), node, valueTaints);
          }
        }
        c(node.right, _state);
      }
    },
    CallExpression(node: any, _state: any, c: any) {
      const calleeName = getCalleeName(node.callee) || "";
      const args = node.arguments || [];
      const argTaints = args.map((arg: any) => evaluateExpression(arg, taints));

      if (calleeName) {
        if (SINK_CALLS.has(calleeName)) {
          recordSinkTraces(traces, filePath, calleeName, node, mergeTaints(argTaints));
        }
        if (calleeName === "setTimeout" || calleeName === "setInterval") {
          recordSinkTraces(traces, filePath, calleeName, node, mergeTaints(argTaints));
        }
        if (calleeName.endsWith(".setTimeout") || calleeName.endsWith(".setInterval")) {
          recordSinkTraces(traces, filePath, calleeName, node, mergeTaints(argTaints));
        }
        if (calleeName.endsWith(".postMessage")) {
          recordSinkTraces(traces, filePath, "postMessage", node, mergeTaints(argTaints));
        }
        if (calleeName.endsWith(".write") || calleeName.endsWith(".writeln")) {
          recordSinkTraces(traces, filePath, calleeName, node, mergeTaints(argTaints));
        }
        if (calleeName.endsWith(".insertAdjacentHTML")) {
          recordSinkTraces(traces, filePath, "insertAdjacentHTML", node, mergeTaints(argTaints));
        }
        if (calleeName.endsWith(".setAttribute")) {
          const attrName = getStringLiteral(args[0]);
          if (attrName) {
            const attr = attrName.toLowerCase();
            if (["href", "src", "srcdoc", "action", "formaction", "data", "style"].includes(attr)) {
              recordSinkTraces(traces, filePath, `setAttribute:${attr}`, node, argTaints[1] || []);
            }
          }
        }
      }

      if (calleeName && summaries.has(calleeName)) {
        const summary = summaries.get(calleeName)!;
        for (let i = 0; i < summary.params.length; i += 1) {
          const templates = summary.paramTraces[i] || [];
          const taintedArgs = argTaints[i] || [];
          if (!templates.length || !taintedArgs.length) {
            continue;
          }
          for (const taint of taintedArgs) {
            for (const template of templates) {
              const suffix = template.path.slice(1);
              const combined = [...taint.chain, ...suffix];
              traces.push({
                filePath,
                source: taint.source,
                sink: template.sink,
                path: combined,
              });
            }
          }
        }
      }

      for (const arg of args) {
        c(arg, _state);
      }
    },
    NewExpression(node: any, _state: any, c: any) {
      const calleeName = getCalleeName(node.callee) || "";
      const args = node.arguments || [];
      const argTaints = mergeTaints(args.map((arg: any) => evaluateExpression(arg, taints)));
      if (calleeName === "Function") {
        recordSinkTraces(traces, filePath, "Function", node, argTaints);
      }
      for (const arg of args) {
        c(arg, _state);
      }
    },
    Property(node: any, _state: any, c: any) {
      const keyName = getStringLiteral(node.key);
      if (keyName === "dangerouslySetInnerHTML") {
        if (node.value && node.value.type === "ObjectExpression") {
          for (const prop of node.value.properties || []) {
            const propName = getStringLiteral(prop && prop.key);
            if (propName === "__html") {
              const valueTaints = evaluateExpression(prop.value, taints);
              recordSinkTraces(traces, filePath, "dangerouslySetInnerHTML", node, valueTaints);
            }
          }
        } else {
          const valueTaints = evaluateExpression(node.value, taints);
          recordSinkTraces(traces, filePath, "dangerouslySetInnerHTML", node, valueTaints);
        }
      }
      if (node.value) {
        c(node.value, _state);
      }
    },
    FunctionDeclaration(node: any, _state: any, _c: any) {
      if (!skipNested && node.body) {
        walk.recursive(node.body, _state, visitors, walk.base);
      }
    },
    FunctionExpression(node: any, _state: any, _c: any) {
      if (!skipNested && node.body) {
        walk.recursive(node.body, _state, visitors, walk.base);
      }
    },
    ArrowFunctionExpression(node: any, _state: any, _c: any) {
      if (!skipNested && node.body) {
        walk.recursive(node.body, _state, visitors, walk.base);
      }
    },
  };

  walk.recursive(node, {}, visitors, walk.base);
  return traces;
}

function buildCallGraph(ast: any, filePath: string): { callGraph: CallGraphEdge[]; functions: Map<string, any> } {
  const callGraph: CallGraphEdge[] = [];
  const functions = new Map<string, any>();

  walk.fullAncestor(ast, (node: any, _state: any, ancestors: any[]) => {
    if (isFunctionNode(node)) {
      const name = getFunctionName(node, ancestors);
      if (!functions.has(name)) {
        functions.set(name, node);
      }
      return;
    }
    if (node.type === "CallExpression") {
      const callee = getCalleeName(node.callee);
      if (!callee) {
        return;
      }
      let caller = "<top>";
      for (let i = ancestors.length - 1; i >= 0; i -= 1) {
        const ancestor = ancestors[i];
        if (isFunctionNode(ancestor)) {
          caller = getFunctionName(ancestor, ancestors.slice(0, i + 1));
          break;
        }
      }
      callGraph.push({
        caller,
        callee,
        filePath,
        location: toLocation(node),
      });
    }
  });

  return { callGraph, functions };
}

function buildFunctionSummaries(functions: Map<string, any>, filePath: string): Map<string, FunctionSummary> {
  const summaries = new Map<string, FunctionSummary>();
  const fnEntries = Array.from(functions.entries());
  for (const [name, fn] of fnEntries) {
    summaries.set(name, { params: getParamNames(fn), paramTraces: {} });
  }
  const passes = 2;
  for (let pass = 0; pass < passes; pass += 1) {
    for (const [name, fn] of fnEntries) {
      const params = getParamNames(fn);
      const initialTaints = new Map<string, TaintPath[]>();
      for (const param of params) {
        const source: FlowEndpoint = { label: `param:${param}`, location: toLocation(fn), kind: "param" };
        initialTaints.set(param, [{ source, chain: [source.label] }]);
      }
      const root = fn.body ? fn.body : fn;
      const traces = analyzeTaintFlow(root, filePath, summaries, {
        initialTaints,
        skipNestedFunctions: true,
      });
      const paramTraces: Record<number, { sink: FlowEndpoint; path: string[] }[]> = {};
      for (const trace of traces) {
        if (trace.source.kind !== "param") {
          continue;
        }
        const paramName = trace.source.label.replace("param:", "");
        const index = params.indexOf(paramName);
        if (index === -1) {
          continue;
        }
        if (!paramTraces[index]) {
          paramTraces[index] = [];
        }
        paramTraces[index].push({ sink: trace.sink, path: trace.path });
      }
      summaries.set(name, { params, paramTraces });
    }
  }
  return summaries;
}

export function analyzeJavaScript(
  contents: string,
  filePath: string,
  signatureRules: SignatureRule[] = []
): AnalysisResult {
  const result: AnalysisResult = {
    featureFlags: [],
    data: [],
    hostnames: [],
    extensions: [],
    mimeTypes: [],
    regexes: [],
    graphql: [],
    location: [],
    storage: [],
    cookies: [],
    documentDomain: [],
    windowName: [],
    windowOpen: [],
    urlSearchParams: [],
    restClient: [],
    fetchOptions: [],
    schemas: [],
    dependencies: [],
    endpoints: [],
    sinks: [],
    userSinks: [],
    frameworks: [],
    events: [],
    urls: [],
    paths: [],
    secrets: [],
    signatures: [],
    wordlist: new Set<string>(),
    callGraph: [],
    traces: [],
  };

  let ast: any;
  try {
    ast = acorn.parse(contents, {
      ecmaVersion: "latest",
      sourceType: "module",
      locations: true,
      allowHashBang: true,
    });
  } catch {
    try {
      ast = acorn.parse(contents, {
        ecmaVersion: "latest",
        sourceType: "script",
        locations: true,
        allowHashBang: true,
      });
    } catch {
      return result;
    }
  }

  const frameworks = new Set<string>();

  walk.simple(ast, {
    ImportDeclaration(node: any) {
      if (node.source && typeof node.source.value === "string") {
        const lib = node.source.value.toLowerCase();
        const targets = ["react", "vue", "angular", "svelte", "solid", "preact"];
        for (const target of targets) {
          if (lib.includes(target)) {
            frameworks.add(target);
            result.frameworks.push(buildFinding("framework", target, filePath, node));
          }
        }
        if (!lib.startsWith(".") && !lib.startsWith("/")) {
          result.dependencies.push(buildFinding("dependency", lib, filePath, node));
        }
      }
    },
    Identifier(node: any) {
      if (node && node.name) {
        addWord(result.wordlist, node.name);
        const name = node.name.toLowerCase();
        if (["react", "vue", "angular", "svelte"].includes(name) && !frameworks.has(name)) {
          frameworks.add(name);
          result.frameworks.push(buildFinding("framework", name, filePath, node));
        }
      }
    },
    Literal(node: any) {
      if (typeof node.value === "string") {
        const value = node.value as string;
        addWord(result.wordlist, value);
        const isUrl = isLikelyUrl(value);
        const isPath = isLikelyPath(value);
        if (isUrl) {
          result.urls.push(buildFinding("url", value, filePath, node));
          addWordsFromPath(result.wordlist, value);
          try {
            const urlObj = new URL(value);
            const pathValue = urlObj.pathname || "";
            if (pathValue) {
              const meta = { path_type: "url" };
              result.paths.push(buildFinding("path", pathValue, filePath, node, "url-path", meta));
            }
          } catch {
            // ignore URL parse errors
          }
        } else if (isPath) {
          let pathType = "simple";
          if (value.indexOf("?") !== -1) {
            pathType = "query";
          }
          if (value.indexOf("#") !== -1) {
            pathType = pathType === "simple" ? "fragment" : `${pathType},fragment`;
          }
          if (value.toLowerCase().indexOf("/api") !== -1 || value.toLowerCase().includes("api")) {
            pathType = pathType === "simple" ? "api" : `${pathType},api`;
          }
          const meta = { path_type: pathType };
          result.paths.push(buildFinding("path", value, filePath, node, pathType, meta));
          addWordsFromPath(result.wordlist, value);
        }
        for (const param of extractQueryParams(value)) {
          addWord(result.wordlist, param);
        }
        if (isLikelyHostname(value)) {
          result.hostnames.push(buildFinding("hostname", value, filePath, node));
        }
        const ext = extractExtension(value);
        if (ext) {
          result.extensions.push(buildFinding("extension", ext, filePath, node, value));
        }
        if (isMimeType(value)) {
          result.mimeTypes.push(buildFinding("mime", value, filePath, node));
        }
        const graphql = detectGraphQL(value);
        if (graphql) {
          result.graphql.push(buildFinding("graphql", graphql.label, filePath, node, truncateValue(value)));
        }
        const secretCheck = isLikelySecret(value);
        if (secretCheck.isSecret) {
          const reason = secretCheck.reason || "secret";
          const label = `${truncateValue(value)} (${reason})`;
          result.secrets.push(buildFinding("secret", label, filePath, node, value));
        } else if (!isUrl && !isPath && !isLikelyHostname(value) && !isMimeType(value)) {
          if (looksLikeData(value)) {
            result.data.push(buildFinding("data", truncateValue(value), filePath, node));
          }
        }
        if (signatureRules.length > 0) {
          result.signatures.push(...buildSignatureFindings(value, filePath, node, signatureRules));
        }
      } else if (node.regex) {
        const pattern = node.regex.pattern || "";
        const flags = node.regex.flags || "";
        const label = flags ? `/${pattern}/${flags}` : `/${pattern}/`;
        result.regexes.push(buildFinding("regex", label, filePath, node, "pattern"));
      }
    },
    VariableDeclarator(node: any) {
      const name = node.id && node.id.type === "Identifier" ? node.id.name : "";
      if (name && looksLikeSecretName(name) && node.init) {
        const literal = getStaticString(node.init);
        if (literal && looksSensitiveLiteral(literal)) {
          result.secrets.push(buildFinding("secret", `${truncateValue(literal)} (var-context)`, filePath, node, literal));
        }
      }
      if (name && looksLikeFeatureFlagName(name) && node.init && isToggleLiteral(node.init)) {
        result.featureFlags.push(buildFinding("feature_flag", name, filePath, node, "var"));
      }
      if (node.init && looksLikeSchema(node.init)) {
        result.schemas.push(buildFinding("schema", "object schema", filePath, node));
      }
    },
    ObjectExpression(node: any) {
      if (looksLikeSchema(node)) {
        result.schemas.push(buildFinding("schema", "object schema", filePath, node));
      }
    },
    TemplateLiteral(node: any) {
      if (node.quasis) {
        for (const quasi of node.quasis) {
          const value = quasi.value && quasi.value.raw;
          if (value) {
            addWordsFromPath(result.wordlist, value);
            if (isLikelyHostname(value)) {
              result.hostnames.push(buildFinding("hostname", value, filePath, quasi));
            }
            const ext = extractExtension(value);
            if (ext) {
              result.extensions.push(buildFinding("extension", ext, filePath, quasi, value));
            }
            if (isMimeType(value)) {
              result.mimeTypes.push(buildFinding("mime", value, filePath, quasi));
            }
            const graphql = detectGraphQL(value);
            if (graphql) {
              result.graphql.push(buildFinding("graphql", graphql.label, filePath, quasi, truncateValue(value)));
            }
            const secretCheck = isLikelySecret(value);
            if (secretCheck.isSecret) {
              const reason = secretCheck.reason || "secret";
              const label = `${truncateValue(value)} (${reason})`;
              result.secrets.push(buildFinding("secret", label, filePath, quasi, value));
            } else if (!isLikelyUrl(value) && !isLikelyPath(value)) {
              if (looksLikeData(value)) {
                result.data.push(buildFinding("data", truncateValue(value), filePath, quasi));
              }
            }
            if (signatureRules.length > 0) {
              result.signatures.push(...buildSignatureFindings(value, filePath, quasi, signatureRules));
            }
          }
        }
      }
    },
    TaggedTemplateExpression(node: any) {
      const tagName = getCalleeName(node.tag);
      if (!tagName) {
        return;
      }
      const lower = tagName.toLowerCase();
      if (lower !== "gql" && lower !== "graphql") {
        return;
      }
      const quasi = node.quasi;
      if (quasi && quasi.quasis && quasi.quasis.length > 0) {
        const raw = quasi.quasis.map((q: any) => q.value && q.value.raw).join("");
        if (raw) {
          const graphql = detectGraphQL(raw);
          if (graphql) {
            result.graphql.push(buildFinding("graphql", graphql.label, filePath, node, truncateValue(raw)));
          } else {
            result.graphql.push(buildFinding("graphql", "graphql:tagged", filePath, node, truncateValue(raw)));
          }
        }
      }
    },
    CallExpression(node: any) {
      const callee = node.callee;
      const args = node.arguments || [];
      const argsUserControlled = args.some((arg: any) => isUserControlled(arg));
      const calleeName = getCalleeName(callee) || "";
      if (calleeName) {
        const lower = calleeName.toLowerCase();
        if (
          FEATURE_KEYWORDS.some((keyword) => lower.includes(keyword)) ||
          ["isenabled", "isfeatureenabled", "getflag", "getfeature"].includes(lower)
        ) {
          const flagName = extractEndpointString(args[0]) || getStaticString(args[0]);
          if (flagName) {
            result.featureFlags.push(
              buildFinding("feature_flag", flagName, filePath, args[0], `call:${calleeName}`)
            );
          }
        }
      }
      if (callee.type === "Identifier" && callee.name === "require") {
        const lib = extractEndpointString(args[0]);
        if (lib && !lib.startsWith(".") && !lib.startsWith("/")) {
          result.dependencies.push(buildFinding("dependency", lib, filePath, node));
        }
      }
      if (callee.type === "Identifier" && callee.name === "fetch") {
        const endpoint = extractEndpointString(args[0]);
        if (endpoint) {
          const authHint = extractAuthHintFromOptions(args[1]);
          const meta = authHint ? { auth: authHint } : undefined;
          result.endpoints.push(buildFinding("endpoint", endpoint, filePath, args[0], "fetch", meta));
        }
        const optionsKeys = extractObjectKeys(args[1]);
        if (optionsKeys.length > 0) {
          result.fetchOptions.push(
            buildFinding("fetch_options", "fetch options", filePath, args[1], optionsKeys.join(", "))
          );
        }
      }
      if (callee.type === "Identifier" && callee.name === "URLSearchParams") {
        result.urlSearchParams.push(buildFinding("urlsearchparams", "URLSearchParams", filePath, node));
      }
      if (callee.type === "Identifier" && callee.name === "open") {
        result.windowOpen.push(buildFinding("window_open", "window.open", filePath, node));
      }
      if (callee.type === "Identifier" && callee.name === "axios") {
        const urlLiteral = extractUrlFromOptions(args[0]);
        if (urlLiteral) {
          const authHint = extractAuthHintFromOptions(args[0]);
          const meta = authHint ? { auth: authHint } : undefined;
          result.endpoints.push(buildFinding("endpoint", urlLiteral, filePath, args[0], "axios", meta));
        }
      }
      if (callee.type === "MemberExpression" && callee.property) {
        const prop = callee.property.name || callee.property.value;
        const obj = callee.object;
        const objPath = getMemberPath(obj);
        if (prop === "open" && node.arguments && node.arguments[1]) {
          const endpoint = extractEndpointString(node.arguments[1]);
          if (endpoint) {
            result.endpoints.push(buildFinding("endpoint", endpoint, filePath, node.arguments[1], "XMLHttpRequest"));
          }
        }
        if (prop === "addEventListener" && node.arguments && node.arguments[0]) {
          const eventArg = node.arguments[0];
          if (eventArg.type === "Literal" && typeof eventArg.value === "string") {
            result.events.push(buildFinding("event", eventArg.value, filePath, eventArg));
          }
        }
        if (prop === "test" && obj && obj.type === "Literal" && obj.regex) {
          const pattern = obj.regex.pattern || "";
          const flags = obj.regex.flags || "";
          const label = flags ? `/${pattern}/${flags}` : `/${pattern}/`;
          result.regexes.push(buildFinding("regex", label, filePath, node, "match"));
        }
        if (["match", "search", "replace"].includes(String(prop)) && node.arguments && node.arguments[0]) {
          const candidate = node.arguments[0];
          if (candidate.type === "Literal" && candidate.regex) {
            const pattern = candidate.regex.pattern || "";
            const flags = candidate.regex.flags || "";
            const label = flags ? `/${pattern}/${flags}` : `/${pattern}/`;
            result.regexes.push(buildFinding("regex", label, filePath, node, "match"));
          }
        }
        if (prop === "assign" || prop === "replace" || prop === "reload") {
          const objPath = getMemberPath(obj);
          if (objPath && objPath.includes("location")) {
            result.location.push(buildFinding("location", `location.${prop}`, filePath, node, "assignment"));
          }
        }
        if (prop === "open") {
          const objPath = getMemberPath(obj);
          if (objPath && (objPath === "window" || objPath.endsWith(".window"))) {
            result.windowOpen.push(buildFinding("window_open", "window.open", filePath, node));
          }
        }
        if (SINK_METHODS.has(prop)) {
          const label = String(prop);
          if (prop === "open") {
            if (!objPath || (!objPath.startsWith("window") && !objPath.startsWith("document"))) {
              return;
            }
          }
          if (prop === "write" || prop === "writeln") {
            if (!objPath || objPath.indexOf("document") === -1) {
              return;
            }
          }
          if (DOM_INSERT_METHODS.has(label)) {
            if (!argsUserControlled && !hasHtmlLikeString(args)) {
              return;
            }
          }
          if (prop === "setAttribute") {
            const attrName = getStringLiteral(args[0]);
            if (!attrName) {
              return;
            }
            const attr = attrName.toLowerCase();
            if (!["href", "src", "srcdoc", "action", "formaction", "data", "style"].includes(attr)) {
              return;
            }
            const labelWithAttr = `setAttribute:${attr}`;
            result.sinks.push(buildFinding("sink", labelWithAttr, filePath, node));
            if (isUserControlled(args[1])) {
              result.userSinks.push(buildFinding("user_sink", labelWithAttr, filePath, node));
            }
            return;
          }
          result.sinks.push(buildFinding("sink", label, filePath, node));
          if (argsUserControlled) {
            result.userSinks.push(buildFinding("user_sink", label, filePath, node));
          }
        }
        if (obj && obj.type === "Identifier" && obj.name === "axios") {
          if (["get", "post", "put", "delete", "patch", "request"].includes(prop)) {
            const endpoint = extractEndpointString(args[0]);
            if (endpoint) {
              const authHint = extractAuthHintFromOptions(args[1]);
              const meta = authHint ? { auth: authHint } : undefined;
              result.endpoints.push(buildFinding("endpoint", endpoint, filePath, args[0], "axios", meta));
            }
            if (prop === "request") {
              const candidate = args[0];
              const urlLiteral = extractUrlFromOptions(candidate);
              if (urlLiteral) {
                const authHint = extractAuthHintFromOptions(candidate);
                const meta = authHint ? { auth: authHint } : undefined;
                result.endpoints.push(buildFinding("endpoint", urlLiteral, filePath, candidate, "axios", meta));
              }
            }
          }
        }
        if (obj && obj.type === "Identifier" && obj.name !== "axios" && HTTP_VERBS.has(String(prop))) {
          const endpoint = extractEndpointString(args[0]);
          if (endpoint) {
            result.restClient.push(buildFinding("rest_client", endpoint, filePath, args[0], `.${prop}`));
          }
        }
        if (obj && obj.type === "Identifier" && (obj.name === "$" || obj.name === "jQuery")) {
          if (["ajax", "get", "post", "getJSON", "getScript"].includes(prop)) {
            let endpoint: string | null = null;
            if (prop === "ajax") {
              endpoint = extractUrlFromOptions(args[0]) || extractEndpointString(args[0]);
            } else {
              endpoint = extractEndpointString(args[0]);
            }
            if (endpoint) {
              result.endpoints.push(buildFinding("endpoint", endpoint, filePath, args[0], `jquery.${prop}`));
            }
          }
        }
        if (obj && obj.type === "Identifier" && obj.name === "navigator" && prop === "sendBeacon") {
          const endpoint = extractEndpointString(args[0]);
          if (endpoint) {
            result.endpoints.push(buildFinding("endpoint", endpoint, filePath, args[0], "sendBeacon"));
          }
        }
        if (prop === "setTimeout" || prop === "setInterval") {
          result.sinks.push(buildFinding("sink", String(prop), filePath, node));
          if (argsUserControlled) {
            result.userSinks.push(buildFinding("user_sink", String(prop), filePath, node));
          }
        }
      }
      if (callee.type === "Identifier" && SINK_CALLS.has(callee.name)) {
        result.sinks.push(buildFinding("sink", callee.name, filePath, node));
        if (argsUserControlled) {
          result.userSinks.push(buildFinding("user_sink", callee.name, filePath, node));
        }
      }
    },
    NewExpression(node: any) {
      const callee = node.callee;
      if (callee.type === "Identifier" && callee.name === "WebSocket") {
        const endpoint = extractEndpointString(node.arguments && node.arguments[0]);
        if (endpoint) {
          result.endpoints.push(buildFinding("endpoint", endpoint, filePath, node.arguments[0], "WebSocket"));
        }
      }
      if (callee.type === "Identifier" && callee.name === "EventSource") {
        const endpoint = extractEndpointString(node.arguments && node.arguments[0]);
        if (endpoint) {
          result.endpoints.push(buildFinding("endpoint", endpoint, filePath, node.arguments[0], "EventSource"));
        }
      }
      if (callee.type === "Identifier" && callee.name === "Function") {
        result.sinks.push(buildFinding("sink", "Function", filePath, node));
        if (node.arguments && node.arguments.some((arg: any) => isUserControlled(arg))) {
          result.userSinks.push(buildFinding("user_sink", "Function", filePath, node));
        }
      }
      if (callee.type === "Identifier" && callee.name === "URLSearchParams") {
        result.urlSearchParams.push(buildFinding("urlsearchparams", "URLSearchParams", filePath, node));
      }
      if (callee.type === "Identifier" && callee.name === "RegExp") {
        const pattern = getStaticString(node.arguments && node.arguments[0]) || "";
        if (pattern) {
          result.regexes.push(buildFinding("regex", `/${pattern}/`, filePath, node, "pattern"));
        }
      }
    },
    MemberExpression(node: any) {
      const path = getMemberPath(node);
      if (path) {
        if (looksLikeFeatureFlagPath(path)) {
          result.featureFlags.push(buildFinding("feature_flag", path, filePath, node, "member"));
        }
        if (path === "document.cookie") {
          result.cookies.push(buildFinding("cookie", "document.cookie", filePath, node, "read"));
        }
        if (path === "document.domain") {
          result.documentDomain.push(buildFinding("document_domain", "document.domain", filePath, node, "read"));
        }
        if (path === "window.name") {
          result.windowName.push(buildFinding("window_name", "window.name", filePath, node, "read"));
        }
        if (path === "window.location" || path === "document.location" || path.startsWith("location.")) {
          result.location.push(buildFinding("location", path, filePath, node, "read"));
        }
      }
      if (node.object && node.object.type === "Identifier") {
        if (node.object.name === "localStorage") {
          result.sinks.push(buildFinding("sink", "localStorage", filePath, node));
          result.storage.push(buildFinding("storage", "localStorage", filePath, node));
        }
        if (node.object.name === "sessionStorage") {
          result.sinks.push(buildFinding("sink", "sessionStorage", filePath, node));
          result.storage.push(buildFinding("storage", "sessionStorage", filePath, node));
        }
        if (node.object.name === "crypto") {
          result.sinks.push(buildFinding("sink", "crypto", filePath, node));
        }
      }
      if (
        node.object &&
        node.object.type === "MemberExpression" &&
        node.object.object &&
        node.object.object.type === "Identifier" &&
        node.object.object.name === "window" &&
        node.object.property &&
        node.object.property.name === "crypto"
      ) {
        result.sinks.push(buildFinding("sink", "crypto", filePath, node));
      }
    },
    AssignmentExpression(node: any) {
      if (node.left && node.left.type === "MemberExpression") {
        const left = node.left;
        const leftPath = getMemberPath(left);
        if (left.object && left.object.type === "Identifier" && left.object.name === "window") {
          if (left.property && left.property.name === "onmessage") {
            result.events.push(buildFinding("event", "window.onmessage", filePath, node));
          }
          if (left.property && left.property.name === "onhashchange") {
            result.events.push(buildFinding("event", "window.onhashchange", filePath, node));
          }
        }
        const propName = left.property && (left.property.name || left.property.value);
        if (propName && SINK_ASSIGNMENTS.has(String(propName))) {
          result.sinks.push(buildFinding("sink", String(propName), filePath, node));
          if (isUserControlled(node.right)) {
            result.userSinks.push(buildFinding("user_sink", String(propName), filePath, node));
          }
        }
        if (leftPath) {
          if (leftPath === "document.cookie") {
            result.cookies.push(buildFinding("cookie", "document.cookie", filePath, node, "assignment"));
          }
          if (leftPath === "document.domain") {
            result.documentDomain.push(buildFinding("document_domain", "document.domain", filePath, node, "assignment"));
          }
          if (leftPath === "window.name") {
            result.windowName.push(buildFinding("window_name", "window.name", filePath, node, "assignment"));
          }
          if (leftPath.startsWith("location.") || leftPath === "window.location" || leftPath === "document.location") {
            result.location.push(buildFinding("location", leftPath, filePath, node, "assignment"));
          }
          if (looksLikeSecretName(leftPath)) {
            const literal = getStaticString(node.right);
            if (literal && looksSensitiveLiteral(literal)) {
              result.secrets.push(buildFinding("secret", `${truncateValue(literal)} (assign-context)`, filePath, node, literal));
            }
          }
        }
      } else if (node.left && node.left.type === "Identifier") {
        const name = node.left.name;
        if (looksLikeSecretName(name)) {
          const literal = getStaticString(node.right);
          if (literal && looksSensitiveLiteral(literal)) {
            result.secrets.push(buildFinding("secret", `${truncateValue(literal)} (assign-context)`, filePath, node, literal));
          }
        }
      }
    },
    Property(node: any) {
      const keyName = getStringLiteral(node.key);
      if (keyName === "dangerouslySetInnerHTML") {
        result.sinks.push(buildFinding("sink", "dangerouslySetInnerHTML", filePath, node));
        if (hasUserControlledHtml(node.value)) {
          result.userSinks.push(buildFinding("user_sink", "dangerouslySetInnerHTML", filePath, node));
        }
      }
      if (keyName) {
        const lower = keyName.toLowerCase();
        if (looksLikeFeatureFlagContainer(lower) && node.value && node.value.type === "ObjectExpression") {
          for (const prop of node.value.properties || []) {
            const flagName = getStringLiteral(prop && prop.key);
            if (!flagName) {
              continue;
            }
            if (prop.value && (isToggleLiteral(prop.value) || looksLikeFeatureFlagName(flagName))) {
              result.featureFlags.push(
                buildFinding("feature_flag", flagName, filePath, prop, `container:${keyName}`)
              );
            }
          }
        } else if (looksLikeFeatureFlagName(keyName) && node.value && isToggleLiteral(node.value)) {
          result.featureFlags.push(buildFinding("feature_flag", keyName, filePath, node, "property"));
        }
      }
      if (keyName && looksLikeSecretName(keyName) && node.value) {
        const literal = getStaticString(node.value);
        if (literal && looksSensitiveLiteral(literal)) {
          result.secrets.push(buildFinding("secret", `${truncateValue(literal)} (key-context)`, filePath, node, literal));
        }
      }
    },
  });

  const flow = buildCallGraph(ast, filePath);
  const summaries = buildFunctionSummaries(flow.functions, filePath);
  const traces: FlowTrace[] = [];
  traces.push(
    ...analyzeTaintFlow(ast, filePath, summaries, {
      skipNestedFunctions: true,
    })
  );
  for (const fn of flow.functions.values()) {
    const root = fn.body ? fn.body : fn;
    traces.push(
      ...analyzeTaintFlow(root, filePath, summaries, {
        skipNestedFunctions: true,
      })
    );
  }
  result.callGraph = flow.callGraph;
  result.traces = traces;

  return result;
}
