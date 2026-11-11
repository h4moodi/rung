import type { ReactNode } from "react";
import { capitalize } from "@/lib/format";
import type { Severity, Stage } from "@/lib/types";

/** Each severity has its own shape, so the level never depends on colour alone. */
function SeverityShape({ severity }: { severity: Severity }) {
  const common = { width: 12, height: 12, viewBox: "0 0 12 12", "aria-hidden": true } as const;
  switch (severity) {
    case "critical":
      return (
        <svg {...common}>
          <path d="M6 0l6 6-6 6-6-6z" fill="currentColor" />
        </svg>
      );
    case "high":
      return (
        <svg {...common}>
          <path d="M6 1l6 10H0z" fill="currentColor" />
        </svg>
      );
    case "medium":
      return (
        <svg {...common}>
          <rect x="1" y="1" width="10" height="10" fill="currentColor" />
        </svg>
      );
    case "low":
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="5" fill="currentColor" />
        </svg>
      );
    default:
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="4" fill="none" stroke="currentColor" strokeWidth="2" />
        </svg>
      );
  }
}

export function SeverityBadge({ severity, count }: { severity: Severity; count?: number }) {
  return (
    <span className={`sev-${severity} inline-flex items-center gap-1.5 whitespace-nowrap text-sm font-semibold`}>
      <SeverityShape severity={severity} />
      {count !== undefined && <span>{count}</span>}
      <span>{severity}</span>
    </span>
  );
}

export function StageBadge({ stage }: { stage: Stage }) {
  return (
    <span className="inline-block whitespace-nowrap border border-ink px-1.5 py-0.5 text-xs font-semibold">
      {capitalize(stage)}
    </span>
  );
}

export function MetMark({ met }: { met: boolean }) {
  return (
    <span className="inline-flex items-center gap-1 font-semibold">
      <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
        {met ? (
          <path d="M2 7.5l3.2 3.2L12 3.5" fill="none" stroke="currentColor" strokeWidth="2.4" />
        ) : (
          <path d="M3 3l8 8M11 3l-8 8" fill="none" stroke="currentColor" strokeWidth="2.4" />
        )}
      </svg>
      {met ? "Met" : "Not met"}
    </span>
  );
}

export function Notice({
  tone = "info",
  title,
  children,
}: {
  tone?: "info" | "error";
  title: string;
  children?: ReactNode;
}) {
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={`border-l-4 bg-surface px-4 py-3 ${tone === "error" ? "border-[var(--sev-critical)]" : "border-accent"}`}
    >
      <p className="font-semibold">{title}</p>
      {children && <div className="mt-1 text-sm text-muted">{children}</div>}
    </div>
  );
}

export function Loading({ label }: { label: string }) {
  return (
    <p role="status" className="flex items-center gap-2 text-muted">
      <svg className="spin" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
        <circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" strokeWidth="2" strokeDasharray="26 12" />
      </svg>
      {label}
    </p>
  );
}

export function ApiDown() {
  return (
    <Notice tone="error" title="The rung API is not reachable.">
      Start it with <code className="code text-ink">rung serve</code> and reload this page. The{" "}
      sample report works without it.
    </Notice>
  );
}
