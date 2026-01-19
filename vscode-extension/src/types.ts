export type FindingKind =
  | "feature_flag"
  | "data"
  | "hostname"
  | "extension"
  | "mime"
  | "regex"
  | "graphql"
  | "location"
  | "storage"
  | "cookie"
  | "document_domain"
  | "window_name"
  | "window_open"
  | "urlsearchparams"
  | "rest_client"
  | "fetch_options"
  | "schema"
  | "dependency"
  | "endpoint"
  | "sink"
  | "user_sink"
  | "framework"
  | "event"
  | "url"
  | "path"
  | "secret"
  | "signature"
  | "sourcemap";

export interface Location {
  line: number;
  column: number;
}

export interface AssetIndexEntry {
  url: string;
  method: string;
  status_code: number;
  timestamp: string;
  content_type: string;
  asset_type?: "js" | "html";
  referer?: string;
  host?: string;
  path?: string;
  first_seen?: string;
  last_seen?: string;
  seen_count?: number;
  original_filename?: string;
  sha256: string;
  sourcemap_ref?: string;
  raw_path: string;
  beautified_path?: string;
  sourcemap_path?: string;
  resolved_dir?: string;
  html_path?: string;
  script_srcs?: string[];
  inline_script_count?: number;
  discovered_from?: string;
  chunk_candidates?: string[];
  observations?: Observation[];
}

export interface Finding {
  kind: FindingKind;
  label: string;
  detail?: string;
  filePath: string;
  location?: Location;
  meta?: Record<string, string>;
}

export interface SourcemapResult {
  sourcemapPath?: string;
  resolvedFiles: string[];
  resolvedStats?: Record<string, SourcemapStats>;
}

export interface AnalysisResult {
  featureFlags: Finding[];
  data: Finding[];
  hostnames: Finding[];
  extensions: Finding[];
  mimeTypes: Finding[];
  regexes: Finding[];
  graphql: Finding[];
  location: Finding[];
  storage: Finding[];
  cookies: Finding[];
  documentDomain: Finding[];
  windowName: Finding[];
  windowOpen: Finding[];
  urlSearchParams: Finding[];
  restClient: Finding[];
  fetchOptions: Finding[];
  schemas: Finding[];
  dependencies: Finding[];
  endpoints: Finding[];
  sinks: Finding[];
  userSinks: Finding[];
  frameworks: Finding[];
  events: Finding[];
  urls: Finding[];
  paths: Finding[];
  secrets: Finding[];
  signatures: Finding[];
  wordlist: Set<string>;
  callGraph: CallGraphEdge[];
  traces: FlowTrace[];
}

export interface AssetAnalysis {
  asset: AssetIndexEntry;
  analysis: AnalysisResult;
  analysisPath: string;
  sourcemap?: SourcemapResult;
  htmlReferrers?: string[];
}

export interface Observation {
  key?: string;
  url: string;
  method: string;
  referer?: string;
  first_seen?: string;
  last_seen?: string;
  count?: number;
  status_code?: number;
  content_type?: string;
}

export interface StoreSnapshot {
  assets: AssetAnalysis[];
  htmlAssets: HtmlAsset[];
  featureFlags: Finding[];
  data: Finding[];
  hostnames: Finding[];
  extensions: Finding[];
  mimeTypes: Finding[];
  regexes: Finding[];
  graphql: Finding[];
  location: Finding[];
  storage: Finding[];
  cookies: Finding[];
  documentDomain: Finding[];
  windowName: Finding[];
  windowOpen: Finding[];
  urlSearchParams: Finding[];
  restClient: Finding[];
  fetchOptions: Finding[];
  schemas: Finding[];
  dependencies: Finding[];
  endpoints: Finding[];
  sinks: Finding[];
  userSinks: Finding[];
  frameworks: Finding[];
  events: Finding[];
  urls: Finding[];
  paths: Finding[];
  secrets: Finding[];
  signatures: Finding[];
  routes: RouteEntry[];
  drift: DriftEntry[];
  alerts: AlertEntry[];
  triage: TriageEntry[];
  coverage: CoverageSummary;
  clusters: EndpointCluster[];
  callGraph: CallGraphEdge[];
  traces: FlowTrace[];
  sourcemapGraph: SourcemapGraphEntry[];
  sourcemaps: { asset: AssetAnalysis; files: string[] }[];
  wordlist: string[];
}

export interface HtmlAsset {
  asset: AssetIndexEntry;
  htmlPath: string;
  scriptSrcs: string[];
  inlineScripts: number;
}

export interface SourcemapStats {
  endpoints: number;
  sinks: number;
  userSinks: number;
  secrets: number;
}

export interface RouteEntry {
  route: string;
  assets: AssetAnalysis[];
}

export interface DriftEntry {
  url: string;
  fromTimestamp?: string;
  toTimestamp?: string;
  fromPath?: string;
  toPath?: string;
  added: {
    endpoints: Finding[];
    sinks: Finding[];
    userSinks: Finding[];
    secrets: Finding[];
    paths: Finding[];
    urls: Finding[];
  };
}

export interface CallGraphEdge {
  caller: string;
  callee: string;
  filePath: string;
  location?: Location;
}

export interface FlowEndpoint {
  label: string;
  location?: Location;
  kind?: "source" | "param";
}

export interface FlowTrace {
  filePath: string;
  source: FlowEndpoint;
  sink: FlowEndpoint;
  path: string[];
}

export interface EndpointCluster {
  basePath: string;
  authHint: string;
  endpoints: Finding[];
}

export interface SourcemapGraphEntry {
  assetUrl: string;
  assetPath: string;
  sourcemapPath?: string;
  resolved: Array<{
    filePath: string;
    endpoints: number;
    sinks: number;
    userSinks: number;
    secrets: number;
  }>;
}

export interface SignatureRule {
  id: string;
  kind?: FindingKind;
  pattern: string;
  flags?: string;
  label?: string;
  description?: string;
}

export interface AlertEntry {
  url: string;
  severity: "low" | "medium" | "high" | "critical";
  summary: string;
  details: string[];
}

export interface TriageEntry {
  url: string;
  filePath: string;
  score: number;
  severity: "low" | "medium" | "high" | "critical";
  reasons: string[];
}

export interface CoverageEntry {
  label: string;
  endpoints: number;
  sinks: number;
  userSinks: number;
  secrets: number;
  signatures: number;
  total: number;
}

export interface CoverageSummary {
  assets: number;
  routes: number;
  coverage: CoverageEntry[];
  totals: CoverageEntry;
}
