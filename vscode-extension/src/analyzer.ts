import * as acorn from "acorn";
import * as walk from "acorn-walk";
import { AnalysisResult, Finding, SignatureRule } from "./types";
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

function buildFinding(kind: Finding["kind"], label: string, filePath: string, node?: any, detail?: string): Finding {
  return {
    kind,
    label,
    detail,
    filePath,
    location: toLocation(node),
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

function isLikelySecret(value: string): { isSecret: boolean; reason: string } {
  if (value.length < 20) {
    return { isSecret: false, reason: "" };
  }
  for (const prefix of SECRET_PREFIXES) {
    if (value.startsWith(prefix)) {
      return { isSecret: true, reason: "known-prefix" };
    }
  }
  const entropy = shannonEntropy(value);
  if (entropy >= 3.8 && (isBase64ish(value) || isHexish(value) || value.length > 32)) {
    return { isSecret: true, reason: "high-entropy" };
  }
  return { isSecret: false, reason: "" };
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

export function analyzeJavaScript(
  contents: string,
  filePath: string,
  signatureRules: SignatureRule[] = []
): AnalysisResult {
  const result: AnalysisResult = {
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
        if (isLikelyUrl(value)) {
          result.urls.push(buildFinding("url", value, filePath, node));
          addWordsFromPath(result.wordlist, value);
        } else if (isLikelyPath(value)) {
          result.paths.push(buildFinding("path", value, filePath, node));
          addWordsFromPath(result.wordlist, value);
        }
        for (const param of extractQueryParams(value)) {
          addWord(result.wordlist, param);
        }
        const secretCheck = isLikelySecret(value);
        if (secretCheck.isSecret) {
          const reason = secretCheck.reason || "secret";
          const label = `${truncateValue(value)} (${reason})`;
          result.secrets.push(buildFinding("secret", label, filePath, node, value));
        }
        if (signatureRules.length > 0) {
          result.signatures.push(...buildSignatureFindings(value, filePath, node, signatureRules));
        }
      }
    },
    TemplateLiteral(node: any) {
      if (node.quasis) {
        for (const quasi of node.quasis) {
          const value = quasi.value && quasi.value.raw;
          if (value) {
            addWordsFromPath(result.wordlist, value);
            const secretCheck = isLikelySecret(value);
            if (secretCheck.isSecret) {
              const reason = secretCheck.reason || "secret";
              const label = `${truncateValue(value)} (${reason})`;
              result.secrets.push(buildFinding("secret", label, filePath, quasi, value));
            }
            if (signatureRules.length > 0) {
              result.signatures.push(...buildSignatureFindings(value, filePath, quasi, signatureRules));
            }
          }
        }
      }
    },
    CallExpression(node: any) {
      const callee = node.callee;
      const args = node.arguments || [];
      const argsUserControlled = args.some((arg: any) => isUserControlled(arg));
      if (callee.type === "Identifier" && callee.name === "fetch") {
        const arg = args[0];
        if (arg && arg.type === "Literal" && typeof arg.value === "string") {
          result.endpoints.push(buildFinding("endpoint", arg.value, filePath, arg, "fetch"));
        }
      }
      if (callee.type === "MemberExpression" && callee.property) {
        const prop = callee.property.name || callee.property.value;
        const obj = callee.object;
        const objPath = getMemberPath(obj);
        if (prop === "open" && node.arguments && node.arguments[1]) {
          const arg = node.arguments[1];
          if (arg.type === "Literal" && typeof arg.value === "string") {
            result.endpoints.push(buildFinding("endpoint", arg.value, filePath, arg, "XMLHttpRequest"));
          }
        }
        if (prop === "addEventListener" && node.arguments && node.arguments[0]) {
          const eventArg = node.arguments[0];
          if (eventArg.type === "Literal" && typeof eventArg.value === "string") {
            result.events.push(buildFinding("event", eventArg.value, filePath, eventArg));
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
            const arg = args[0];
            if (arg && arg.type === "Literal" && typeof arg.value === "string") {
              result.endpoints.push(buildFinding("endpoint", arg.value, filePath, arg, "axios"));
            }
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
        const arg = node.arguments && node.arguments[0];
        if (arg && arg.type === "Literal" && typeof arg.value === "string") {
          result.endpoints.push(buildFinding("endpoint", arg.value, filePath, arg, "WebSocket"));
        }
      }
      if (callee.type === "Identifier" && callee.name === "EventSource") {
        const arg = node.arguments && node.arguments[0];
        if (arg && arg.type === "Literal" && typeof arg.value === "string") {
          result.endpoints.push(buildFinding("endpoint", arg.value, filePath, arg, "EventSource"));
        }
      }
      if (callee.type === "Identifier" && callee.name === "Function") {
        result.sinks.push(buildFinding("sink", "Function", filePath, node));
        if (node.arguments && node.arguments.some((arg: any) => isUserControlled(arg))) {
          result.userSinks.push(buildFinding("user_sink", "Function", filePath, node));
        }
      }
    },
    MemberExpression(node: any) {
      if (node.object && node.object.type === "Identifier") {
        if (node.object.name === "localStorage") {
          result.sinks.push(buildFinding("sink", "localStorage", filePath, node));
        }
        if (node.object.name === "sessionStorage") {
          result.sinks.push(buildFinding("sink", "sessionStorage", filePath, node));
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
        if (left.object && left.object.type === "Identifier" && left.object.name === "window") {
          if (left.property && left.property.name === "onmessage") {
            result.events.push(buildFinding("event", "window.onmessage", filePath, node));
          }
        }
        const propName = left.property && (left.property.name || left.property.value);
        if (propName && SINK_ASSIGNMENTS.has(String(propName))) {
          result.sinks.push(buildFinding("sink", String(propName), filePath, node));
          if (isUserControlled(node.right)) {
            result.userSinks.push(buildFinding("user_sink", String(propName), filePath, node));
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
    },
  });

  return result;
}
