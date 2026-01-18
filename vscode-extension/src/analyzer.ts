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
          const authHint = extractAuthHintFromOptions(args[1]);
          const meta = authHint ? { auth: authHint } : undefined;
          result.endpoints.push(buildFinding("endpoint", arg.value, filePath, arg, "fetch", meta));
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
              const authHint = extractAuthHintFromOptions(args[1]);
              const meta = authHint ? { auth: authHint } : undefined;
              result.endpoints.push(buildFinding("endpoint", arg.value, filePath, arg, "axios", meta));
            }
            if (prop === "request" && arg && arg.type === "ObjectExpression") {
              let urlLiteral: string | null = null;
              let authHint: string | null = extractAuthHintFromOptions(arg);
              for (const propNode of arg.properties || []) {
                const keyName = getStringLiteral(propNode && propNode.key);
                if (keyName === "url" && propNode.value && propNode.value.type === "Literal") {
                  if (typeof propNode.value.value === "string") {
                    urlLiteral = propNode.value.value;
                  }
                }
              }
              if (urlLiteral) {
                const meta = authHint ? { auth: authHint } : undefined;
                result.endpoints.push(buildFinding("endpoint", urlLiteral, filePath, arg, "axios", meta));
              }
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
