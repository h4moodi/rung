import type { Dimension, Finding, Location, Outcome, Priority, Severity, Stage } from "./types";
import { STAGES } from "./types";

export const DIMENSION_LABEL: Record<Dimension, string> = {
  commit_history: "Commit history",
  containerization: "Containerization",
  testing: "Testing",
  ci_cd: "CI/CD",
  documentation: "Documentation",
  security: "Security",
};

export const OUTCOME_LABEL: Record<Outcome, string> = {
  passed: "Passed",
  failed: "Failed",
  not_applicable: "Not applicable",
};

export const PRIORITY_LABEL: Record<Priority, { title: string; hint: string }> = {
  overdue: { title: "Overdue", hint: "Expected at the rung you are on, or below it." },
  next: { title: "Next rung", hint: "What it takes to climb one rung." },
  later: { title: "Later", hint: "Beyond the next rung. Reported as info until you get closer." },
};

const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function severityRank(severity: Severity): number {
  return SEVERITY_RANK[severity] ?? 0;
}

export function stageOrder(stage: Stage): number {
  return STAGES.indexOf(stage);
}

export function capitalize(text: string): string {
  return text.length === 0 ? text : text[0].toUpperCase() + text.slice(1);
}

export function label(key: string, table: Record<string, string>): string {
  return table[key] ?? key;
}

/** 0..1 -> whole percent, never rounding a miss up to the threshold. */
export function percent(fraction: number): number {
  return Math.floor(Math.max(0, Math.min(1, fraction)) * 100 + 1e-6);
}

export function formatScore(score: number): string {
  return Number.isInteger(score) ? String(score) : score.toFixed(1);
}

export function formatLocation(location: Location): string {
  if (location.start_line == null) return location.path;
  if (location.end_line != null && location.end_line !== location.start_line) {
    return `${location.path}:${location.start_line}-${location.end_line}`;
  }
  return `${location.path}:${location.start_line}`;
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.floor(ms / 60_000)} min ${Math.round((ms % 60_000) / 1000)} s`;
}

export function relativeTime(iso: string, now: number): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return iso;
  const seconds = Math.round((then - now) / 1000);
  const format = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  const steps: [Intl.RelativeTimeFormatUnit, number][] = [
    ["year", 31_536_000],
    ["month", 2_592_000],
    ["day", 86_400],
    ["hour", 3600],
    ["minute", 60],
  ];
  for (const [unit, size] of steps) {
    if (Math.abs(seconds) >= size) return format.format(Math.round(seconds / size), unit);
  }
  return "just now";
}

/** Only https URLs with a host and a path are accepted by the audit form. */
export function validateRepoUrl(input: string): string | null {
  const value = input.trim();
  if (value.length === 0) return "Enter the https URL of a repository.";
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "That is not a URL. Example: https://github.com/owner/repo";
  }
  if (url.protocol !== "https:") return "Only https URLs are accepted.";
  if (url.username || url.password) return "Remove the credentials from the URL.";
  if (url.pathname.replace(/\/+$/, "").length < 2) return "Add the repository path, e.g. /owner/repo.";
  return null;
}

export interface FindingFilter {
  severity: Severity | "all";
  dimension: Dimension | "all";
  text: string;
}

export type FindingSort = "severity" | "rule" | "path";

export function filterFindings(findings: readonly Finding[], filter: FindingFilter): Finding[] {
  const needle = filter.text.trim().toLowerCase();
  return findings.filter((f) => {
    if (filter.severity !== "all" && f.severity !== filter.severity) return false;
    if (filter.dimension !== "all" && f.dimension !== filter.dimension) return false;
    if (needle.length === 0) return true;
    return [f.rule_id, f.title, f.message, f.location.path].some((field) =>
      field.toLowerCase().includes(needle),
    );
  });
}

export function sortFindings(findings: readonly Finding[], sort: FindingSort): Finding[] {
  const byRule = (a: Finding, b: Finding) =>
    a.rule_id.localeCompare(b.rule_id) ||
    a.location.path.localeCompare(b.location.path) ||
    (a.location.start_line ?? 0) - (b.location.start_line ?? 0);
  const sorted = [...findings];
  if (sort === "severity") {
    sorted.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || byRule(a, b));
  } else if (sort === "path") {
    sorted.sort(
      (a, b) =>
        a.location.path.localeCompare(b.location.path) ||
        (a.location.start_line ?? 0) - (b.location.start_line ?? 0) ||
        a.rule_id.localeCompare(b.rule_id),
    );
  } else {
    sorted.sort(byRule);
  }
  return sorted;
}

export function downloadJson(filename: string, data: unknown): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename.replace(/[^A-Za-z0-9._-]+/g, "-");
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
