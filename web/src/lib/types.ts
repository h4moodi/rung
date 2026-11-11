// Mirrors src/rung/models.py (SCHEMA_VERSION 1.0). Keep in sync with that file.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export type Stage = "inception" | "stabilization" | "growth" | "maturity";
export type Dimension =
  | "commit_history"
  | "containerization"
  | "testing"
  | "ci_cd"
  | "documentation"
  | "security";
export type Outcome = "passed" | "failed" | "not_applicable";
export type Priority = "overdue" | "next" | "later";

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
export const STAGES: readonly Stage[] = ["inception", "stabilization", "growth", "maturity"];
export const DIMENSIONS: readonly Dimension[] = [
  "commit_history",
  "containerization",
  "testing",
  "ci_cd",
  "documentation",
  "security",
];
export const PRIORITIES: readonly Priority[] = ["overdue", "next", "later"];

export interface Location {
  path: string;
  start_line: number | null;
  end_line: number | null;
}

export interface Finding {
  rule_id: string;
  title: string;
  dimension: Dimension;
  stage: Stage;
  severity: Severity;
  base_severity: Severity;
  confidence: Confidence;
  message: string;
  remediation: string;
  location: Location;
  fingerprint: string;
}

export interface RuleResult {
  rule_id: string;
  title: string;
  dimension: Dimension;
  stage: Stage;
  weight: number;
  severity: Severity;
  confidence: Confidence;
  outcome: Outcome;
  summary: string;
  evidence: Location[];
  finding_count: number;
  error: string | null;
}

export interface DimensionScore {
  dimension: Dimension;
  score: number;
  passed: number;
  failed: number;
  not_applicable: number;
}

export interface StageProgress {
  stage: Stage;
  fulfillment: number;
  passed: number;
  total: number;
  met: boolean;
}

export interface Classification {
  stage: Stage;
  next_stage: Stage | null;
  threshold: number;
  progress: StageProgress[];
  rationale: string;
}

export interface ChecklistItem {
  rank: number;
  rule_id: string;
  title: string;
  dimension: Dimension;
  stage: Stage;
  priority: Priority;
  severity: Severity;
  remediation: string;
  finding_count: number;
}

export interface Suppression {
  fingerprint: string;
  rule_id: string;
  path: string;
  justification: string;
}

export interface RepoInfo {
  name: string;
  source: string;
  is_git: boolean;
  head_commit: string | null;
  head_date: string | null;
  branch: string | null;
  shallow: boolean;
}

export interface ToolInfo {
  name: string;
  version: string;
  schema_version: string;
}

export interface Summary {
  counts_by_severity: Partial<Record<Severity, number>>;
  rules_run: number;
  rules_passed: number;
  rules_failed: number;
  rules_not_applicable: number;
  files_scanned: number;
  commits_analyzed: number;
  suppressed: number;
  duration_ms: number;
}

export interface AuditReport {
  tool: ToolInfo;
  repo: RepoInfo;
  classification: Classification;
  overall_score: number;
  dimensions: DimensionScore[];
  rules: RuleResult[];
  findings: Finding[];
  checklist: ChecklistItem[];
  suppressed: Suppression[];
  summary: Summary;
}

// ---- HTTP API payloads

export interface Health {
  status: string;
  version: string;
}

export interface RuleInfo {
  id: string;
  title: string;
  dimension: Dimension;
  stage: Stage;
  severity: Severity;
  confidence: Confidence;
  weight: number;
  description: string;
  remediation: string;
}

export interface StageInfo {
  stage: Stage;
  title: string;
  summary: string;
  expectations: string[];
}

export interface AuditRecord {
  id: string;
  source: string;
  created_at: string;
  report: AuditReport;
}

export interface AuditListItem {
  id: string;
  source: string;
  created_at: string;
  stage: Stage;
  overall_score: number;
  counts_by_severity: Partial<Record<Severity, number>>;
}
