"use client";

import { useEffect, useId, useMemo, useState } from "react";
import type { CSSProperties } from "react";
import { describeError, getAuditSarif } from "@/lib/api";
import {
  DIMENSION_LABEL,
  OUTCOME_LABEL,
  PRIORITY_LABEL,
  capitalize,
  downloadJson,
  filterFindings,
  formatDuration,
  formatLocation,
  formatScore,
  label,
  percent,
  sortFindings,
  stageOrder,
} from "@/lib/format";
import type { FindingSort } from "@/lib/format";
import { DIMENSIONS, PRIORITIES, SEVERITIES } from "@/lib/types";
import type {
  AuditReport,
  ChecklistItem,
  Classification,
  Dimension,
  DimensionScore,
  Finding,
  Outcome,
  RuleResult,
  Severity,
} from "@/lib/types";
import { MetMark, SeverityBadge, StageBadge } from "./ui";

interface Props {
  report: AuditReport;
  /** Set for stored audits: enables the SARIF download and scopes the checklist state. */
  auditId?: string;
  storageKey: string;
}

export function ReportView({ report, auditId, storageKey }: Props) {
  return (
    <article className="flex flex-col gap-12">
      <ReportHeader report={report} auditId={auditId} />
      <Ladder classification={report.classification} />
      <Dimensions scores={report.dimensions} />
      <Checklist items={report.checklist} storageKey={storageKey} />
      <Findings findings={report.findings} />
      <Rules rules={report.rules} />
      <SummaryFooter report={report} />
    </article>
  );
}

function SectionTitle({ id, children, note }: { id: string; children: string; note?: string }) {
  return (
    <div className="mb-4 border-b-2 border-ink pb-2">
      <h2 id={id} className="wide text-xl">
        {children}
      </h2>
      {note && <p className="mt-1 max-w-prose text-sm text-muted">{note}</p>}
    </div>
  );
}

// ---------------------------------------------------------------------- header

function ReportHeader({ report, auditId }: { report: AuditReport; auditId?: string }) {
  const [sarifError, setSarifError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { repo } = report;
  const base = repo.name || "audit";

  async function downloadSarif() {
    if (!auditId) return;
    setBusy(true);
    setSarifError(null);
    try {
      downloadJson(`${base}.sarif`, await getAuditSarif(auditId));
    } catch (error) {
      setSarifError(describeError(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <header className="grid gap-6 sm:grid-cols-[1fr_auto] sm:items-end">
      <div className="min-w-0">
        <h1 className="wide break-words text-3xl sm:text-4xl">{repo.name}</h1>
        <p className="code mt-2 text-muted">{repo.source}</p>
        <dl className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-sm">
          {repo.head_commit && (
            <div className="flex gap-2">
              <dt className="narrow">Commit</dt>
              <dd className="code">{repo.head_commit.slice(0, 7)}</dd>
            </div>
          )}
          {repo.head_date && (
            <div className="flex gap-2">
              <dt className="narrow">Committed</dt>
              <dd>{repo.head_date.slice(0, 10)}</dd>
            </div>
          )}
          {repo.branch && (
            <div className="flex gap-2">
              <dt className="narrow">Branch</dt>
              <dd className="code">{repo.branch}</dd>
            </div>
          )}
          {!repo.is_git && (
            <div className="flex gap-2">
              <dt className="narrow">History</dt>
              <dd>not a git repository</dd>
            </div>
          )}
          {repo.shallow && (
            <div className="flex gap-2">
              <dt className="narrow">History</dt>
              <dd>shallow clone</dd>
            </div>
          )}
        </dl>
      </div>
      <div className="flex flex-col gap-3 sm:items-end">
        <p className="flex items-baseline gap-2">
          <span className="narrow text-sm">Overall score</span>
          <span className="wide text-5xl">{formatScore(report.overall_score)}</span>
          <span className="text-muted">/ 100</span>
        </p>
        <div className="flex flex-wrap gap-2">
          <button type="button" className="btn" onClick={() => downloadJson(`${base}.rung.json`, report)}>
            Download JSON
          </button>
          {auditId && (
            <button type="button" className="btn" onClick={downloadSarif} disabled={busy}>
              {busy ? "Preparing SARIF" : "Download SARIF"}
            </button>
          )}
        </div>
        {!auditId && (
          <p className="text-sm text-muted">SARIF is available for audits run through the API.</p>
        )}
        {sarifError && (
          <p role="alert" className="sev-critical text-sm font-semibold">
            SARIF download failed: {sarifError}
          </p>
        )}
      </div>
    </header>
  );
}

// ---------------------------------------------------------------------- ladder

export function Ladder({ classification }: { classification: Classification }) {
  const threshold = percent(classification.threshold);
  const rungs = [...classification.progress].sort((a, b) => stageOrder(b.stage) - stageOrder(a.stage));
  const style = { "--threshold": `${classification.threshold * 100}%` } as CSSProperties;

  return (
    <section aria-labelledby="ladder-title">
      <SectionTitle id="ladder-title">The ladder</SectionTitle>
      <p className="mb-6 max-w-prose text-lg">{classification.rationale}</p>
      {rungs.length === 0 ? (
        <p className="text-muted">This report has no stage progress to draw.</p>
      ) : (
        <ol className="ladder max-w-3xl" style={style} aria-label="Stages, highest rung first">
          <li className="ladder-end" aria-hidden="true">
            <div className="ladder-track">
              <span className="ladder-threshold-label narrow text-xs">{threshold}% holds a rung</span>
            </div>
            <div />
          </li>
          {rungs.map((rung, index) => {
            const current = rung.stage === classification.stage;
            const filled = percent(rung.fulfillment);
            const short = Math.max(1, Math.ceil((classification.threshold - rung.fulfillment) * 100));
            return (
              <li
                key={rung.stage}
                className="ladder-rung"
                data-met={rung.met}
                data-current={current}
                aria-current={current ? "step" : undefined}
              >
                <div className="ladder-track" aria-hidden="true">
                  <div className="ladder-bar">
                    <span
                      className="ladder-fill"
                      style={{ width: `${filled}%`, "--step": rungs.length - 1 - index } as CSSProperties}
                    />
                  </div>
                </div>
                <div className="ladder-info">
                  <div className="flex flex-wrap items-baseline justify-between gap-x-4">
                    <h3 className="wide text-lg sm:text-2xl">{capitalize(rung.stage)}</h3>
                    <p className="wide text-2xl sm:text-3xl">
                      {filled}
                      <span className="text-base">%</span>
                    </p>
                  </div>
                  <p className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
                    <MetMark met={rung.met} />
                    <span className="text-muted">
                      {rung.total === 0
                        ? "No applicable rules"
                        : `${rung.passed} of ${rung.total} rules passed`}
                    </span>
                    {!rung.met && <span className="text-muted">{short} points short</span>}
                  </p>
                  {current && (
                    <p className="mt-2 inline-block bg-accent px-2 py-0.5 text-sm font-bold text-on-accent">
                      You are here
                    </p>
                  )}
                </div>
              </li>
            );
          })}
          <li className="ladder-end" aria-hidden="true">
            <div className="ladder-track" />
            <div />
          </li>
        </ol>
      )}
      <p className="mt-4 max-w-prose text-sm text-muted">
        Each bar is the weighted share of that stage&apos;s rules that pass. Solid bars reach the
        dashed {threshold}% line and are met; hatched bars fall short. Your stage is the highest rung
        with every rung below it met.
        {classification.next_stage
          ? ` Next rung: ${classification.next_stage}.`
          : " This is the top of the ladder."}
      </p>
    </section>
  );
}

// ------------------------------------------------------------------ dimensions

function Dimensions({ scores }: { scores: DimensionScore[] }) {
  const size = 220;
  const centre = size / 2;
  const radius = 84;
  const point = (index: number, fraction: number) => {
    const angle = (Math.PI * 2 * index) / Math.max(scores.length, 1) - Math.PI / 2;
    return `${(centre + Math.cos(angle) * radius * fraction).toFixed(1)},${(centre + Math.sin(angle) * radius * fraction).toFixed(1)}`;
  };
  const ring = (fraction: number) => scores.map((_, i) => point(i, fraction)).join(" ");

  return (
    <section aria-labelledby="dimensions-title">
      <SectionTitle id="dimensions-title" note="Weighted share of applicable rules passed in each audited artifact.">
        Dimension scores
      </SectionTitle>
      {scores.length === 0 ? (
        <p className="text-muted">No dimension scores in this report.</p>
      ) : (
        <div className="grid items-center gap-6 md:grid-cols-[220px_1fr]">
          <svg
            viewBox={`0 0 ${size} ${size}`}
            width={size}
            height={size}
            aria-hidden="true"
            className="mx-auto hidden md:block"
          >
            {[0.25, 0.5, 0.75, 1].map((f) => (
              <polygon key={f} points={ring(f)} fill="none" stroke="var(--line)" strokeWidth="1" />
            ))}
            {scores.map((s, i) => (
              <line
                key={s.dimension}
                x1={centre}
                y1={centre}
                x2={point(i, 1).split(",")[0]}
                y2={point(i, 1).split(",")[1]}
                stroke="var(--line)"
              />
            ))}
            <polygon
              points={scores.map((s, i) => point(i, Math.max(0, Math.min(100, s.score)) / 100)).join(" ")}
              fill="var(--accent-soft)"
              stroke="var(--accent)"
              strokeWidth="2.5"
              fillOpacity="0.8"
            />
          </svg>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="narrow text-left">
                  <th scope="col" className="py-1 pr-3 font-semibold">Dimension</th>
                  <th scope="col" className="py-1 pr-3 font-semibold">Score</th>
                  <th scope="col" className="w-2/5 py-1 pr-3 font-semibold max-sm:hidden">
                    <span className="sr-only">Bar</span>
                  </th>
                  <th scope="col" className="py-1 pr-3 text-right font-semibold">Passed</th>
                  <th scope="col" className="py-1 pr-3 text-right font-semibold">Failed</th>
                  <th scope="col" className="py-1 text-right font-semibold">N/A</th>
                </tr>
              </thead>
              <tbody>
                {scores.map((s) => (
                  <tr key={s.dimension} className="border-t border-line">
                    <th scope="row" className="py-2 pr-3 text-left font-semibold">
                      {label(s.dimension, DIMENSION_LABEL)}
                    </th>
                    <td className="py-2 pr-3 text-base font-bold">{formatScore(s.score)}</td>
                    <td className="py-2 pr-3 max-sm:hidden" aria-hidden="true">
                      <div className="h-2.5 border border-ink bg-surface">
                        <div className="h-full bg-accent" style={{ width: `${Math.max(0, Math.min(100, s.score))}%` }} />
                      </div>
                    </td>
                    <td className="py-2 pr-3 text-right">{s.passed}</td>
                    <td className="py-2 pr-3 text-right">{s.failed}</td>
                    <td className="py-2 text-right text-muted">{s.not_applicable}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  );
}

// ------------------------------------------------------------------- checklist

function loadChecked(key: string): string[] {
  try {
    const raw = window.localStorage.getItem(key);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === "string") : [];
  } catch {
    return [];
  }
}

function Checklist({ items, storageKey }: { items: ChecklistItem[]; storageKey: string }) {
  const key = `rung:checklist:${storageKey}`;
  const [checked, setChecked] = useState<string[]>([]);

  useEffect(() => {
    let live = true;
    queueMicrotask(() => {
      if (live) setChecked(loadChecked(key));
    });
    return () => {
      live = false;
    };
  }, [key]);

  function toggle(ruleId: string) {
    setChecked((current) => {
      const next = current.includes(ruleId) ? current.filter((id) => id !== ruleId) : [...current, ruleId];
      try {
        window.localStorage.setItem(key, JSON.stringify(next));
      } catch {
        // Storage can be full or blocked; the checklist still works for this visit.
      }
      return next;
    });
  }

  const done = items.filter((item) => checked.includes(item.rule_id)).length;

  return (
    <section aria-labelledby="checklist-title">
      <SectionTitle
        id="checklist-title"
        note="One item per failed rule, most urgent first. Ticks are saved in this browser only."
      >
        Next steps
      </SectionTitle>
      {items.length === 0 ? (
        <p className="text-muted">Nothing to do: every applicable rule passed.</p>
      ) : (
        <>
          <p className="mb-4 text-sm font-semibold" aria-live="polite">
            {done} of {items.length} done
          </p>
          <div className="flex flex-col gap-8">
            {PRIORITIES.map((priority) => {
              const group = items.filter((item) => item.priority === priority);
              if (group.length === 0) return null;
              return (
                <div key={priority}>
                  <h3 className="text-lg font-bold">
                    {PRIORITY_LABEL[priority].title}{" "}
                    <span className="font-normal text-muted">({group.length})</span>
                  </h3>
                  <p className="mb-2 text-sm text-muted">{PRIORITY_LABEL[priority].hint}</p>
                  <ul className="border-t border-line">
                    {group.map((item) => {
                      const isDone = checked.includes(item.rule_id);
                      const inputId = `check-${item.rule_id}`;
                      return (
                        <li key={item.rule_id} className="flex gap-3 border-b border-line py-3">
                          <input
                            id={inputId}
                            type="checkbox"
                            className="mt-1 h-5 w-5 shrink-0 accent-[var(--accent)]"
                            checked={isDone}
                            onChange={() => toggle(item.rule_id)}
                          />
                          <div className={`min-w-0 ${isDone ? "opacity-60" : ""}`}>
                            <label htmlFor={inputId} className={`font-semibold ${isDone ? "line-through" : ""}`}>
                              {item.title}
                            </label>
                            <p className="mt-0.5 max-w-prose text-sm">{item.remediation}</p>
                            <p className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted">
                              <SeverityBadge severity={item.severity} />
                              <span className="code">{item.rule_id}</span>
                              <span>{label(item.dimension, DIMENSION_LABEL)}</span>
                              <StageBadge stage={item.stage} />
                              <span>
                                {item.finding_count} {item.finding_count === 1 ? "finding" : "findings"}
                              </span>
                            </p>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              );
            })}
          </div>
        </>
      )}
    </section>
  );
}

// -------------------------------------------------------------------- findings

function Findings({ findings }: { findings: Finding[] }) {
  const uid = useId();
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [dimension, setDimension] = useState<Dimension | "all">("all");
  const [text, setText] = useState("");
  const [sort, setSort] = useState<FindingSort>("severity");
  const [open, setOpen] = useState<string[]>([]);

  const shown = useMemo(
    () => sortFindings(filterFindings(findings, { severity, dimension, text }), sort),
    [findings, severity, dimension, text, sort],
  );

  return (
    <section aria-labelledby="findings-title">
      <SectionTitle id="findings-title">Findings</SectionTitle>
      {findings.length === 0 ? (
        <p className="text-muted">No findings. Nothing was reported above the baseline.</p>
      ) : (
        <>
          <div className="mb-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <label className="flex flex-col gap-1 text-sm" htmlFor={`${uid}-text`}>
              <span className="narrow">Search</span>
              <input
                id={`${uid}-text`}
                type="search"
                className="field"
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder="Rule, message or path"
              />
            </label>
            <label className="flex flex-col gap-1 text-sm" htmlFor={`${uid}-sev`}>
              <span className="narrow">Severity</span>
              <select
                id={`${uid}-sev`}
                className="field"
                value={severity}
                onChange={(e) => setSeverity(e.target.value as Severity | "all")}
              >
                <option value="all">All severities</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>{capitalize(s)}</option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-sm" htmlFor={`${uid}-dim`}>
              <span className="narrow">Dimension</span>
              <select
                id={`${uid}-dim`}
                className="field"
                value={dimension}
                onChange={(e) => setDimension(e.target.value as Dimension | "all")}
              >
                <option value="all">All dimensions</option>
                {DIMENSIONS.map((d) => (
                  <option key={d} value={d}>{DIMENSION_LABEL[d]}</option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-sm" htmlFor={`${uid}-sort`}>
              <span className="narrow">Sort by</span>
              <select
                id={`${uid}-sort`}
                className="field"
                value={sort}
                onChange={(e) => setSort(e.target.value as FindingSort)}
              >
                <option value="severity">Severity, worst first</option>
                <option value="rule">Rule id</option>
                <option value="path">Path</option>
              </select>
            </label>
          </div>
          <p className="mb-2 text-sm text-muted" aria-live="polite">
            Showing {shown.length} of {findings.length}
          </p>
          {shown.length === 0 ? (
            <p className="border-t border-line py-4 text-muted">No findings match these filters.</p>
          ) : (
            <ul className="border-t border-line">
              {shown.map((finding, index) => {
                const rowKey = `${finding.fingerprint}:${finding.location.start_line ?? ""}:${index}`;
                const isOpen = open.includes(rowKey);
                const panelId = `${uid}-f-${index}`;
                const downgraded = finding.severity !== finding.base_severity;
                return (
                  <li key={rowKey} className="border-b border-line">
                    <button
                      type="button"
                      className="grid w-full cursor-pointer grid-cols-[1fr_auto] gap-x-4 gap-y-1 py-3 text-left hover:bg-surface sm:grid-cols-[7rem_5rem_1fr_auto]"
                      aria-expanded={isOpen}
                      aria-controls={panelId}
                      onClick={() =>
                        setOpen((cur) => (isOpen ? cur.filter((k) => k !== rowKey) : [...cur, rowKey]))
                      }
                    >
                      <SeverityBadge severity={finding.severity} />
                      <span className="code font-semibold max-sm:col-start-1">{finding.rule_id}</span>
                      <span className="min-w-0 max-sm:col-span-2">
                        <span className="block break-words">{finding.message}</span>
                        <span className="code mt-0.5 block text-muted">{formatLocation(finding.location)}</span>
                      </span>
                      <span className="narrow text-sm max-sm:col-start-2 max-sm:row-start-1" aria-hidden="true">
                        {isOpen ? "Hide" : "Fix"}
                      </span>
                    </button>
                    {isOpen && (
                      <div id={panelId} className="mb-3 border-l-4 border-accent bg-surface px-4 py-3 text-sm">
                        <p className="font-semibold">{finding.title}</p>
                        <p className="mt-1 max-w-prose">{finding.remediation}</p>
                        <p className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-muted">
                          <span>Confidence: {finding.confidence}</span>
                          <span>{label(finding.dimension, DIMENSION_LABEL)}</span>
                          <span>Expected from {finding.stage}</span>
                        </p>
                        {downgraded && (
                          <p className="mt-2">
                            Downgraded from {finding.base_severity}: not expected until {finding.stage}.
                          </p>
                        )}
                      </div>
                    )}
                    {!isOpen && downgraded && (
                      <p className="-mt-2 pb-3 text-sm text-muted sm:pl-[13rem]">
                        Downgraded from {finding.base_severity}: not expected until {finding.stage}.
                      </p>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </>
      )}
    </section>
  );
}

// ----------------------------------------------------------------------- rules

function OutcomeMark({ outcome }: { outcome: Outcome }) {
  const glyph = outcome === "passed" ? "M2 7.5l3.2 3.2L12 3.5" : outcome === "failed" ? "M3 3l8 8M11 3l-8 8" : "M3 7h8";
  return (
    <span className={`inline-flex items-center gap-1 whitespace-nowrap text-sm font-semibold ${outcome === "not_applicable" ? "text-muted" : ""}`}>
      <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
        <path d={glyph} fill="none" stroke="currentColor" strokeWidth="2.4" />
      </svg>
      {OUTCOME_LABEL[outcome] ?? outcome}
    </span>
  );
}

function Rules({ rules }: { rules: RuleResult[] }) {
  const uid = useId();
  const [outcome, setOutcome] = useState<Outcome | "all">("all");
  const shown = outcome === "all" ? rules : rules.filter((r) => r.outcome === outcome);
  const count = (o: Outcome) => rules.filter((r) => r.outcome === o).length;

  return (
    <section aria-labelledby="rules-title">
      <SectionTitle id="rules-title" note="Every rule that ran, including the ones that passed and the evidence for them.">
        Rules
      </SectionTitle>
      {rules.length === 0 ? (
        <p className="text-muted">No rules ran for this report.</p>
      ) : (
        <>
          <label className="mb-3 flex max-w-xs flex-col gap-1 text-sm" htmlFor={`${uid}-outcome`}>
            <span className="narrow">Outcome</span>
            <select
              id={`${uid}-outcome`}
              className="field"
              value={outcome}
              onChange={(e) => setOutcome(e.target.value as Outcome | "all")}
            >
              <option value="all">All outcomes ({rules.length})</option>
              <option value="passed">Passed ({count("passed")})</option>
              <option value="failed">Failed ({count("failed")})</option>
              <option value="not_applicable">Not applicable ({count("not_applicable")})</option>
            </select>
          </label>
          {shown.length === 0 ? (
            <p className="border-t border-line py-4 text-muted">No rules with this outcome.</p>
          ) : (
            <ul className="border-t border-line">
              {shown.map((rule) => (
                <li
                  key={rule.rule_id}
                  className="grid gap-x-4 gap-y-1 border-b border-line py-2.5 sm:grid-cols-[9rem_5rem_1fr]"
                >
                  <OutcomeMark outcome={rule.outcome} />
                  <span className="code font-semibold">{rule.rule_id}</span>
                  <div className="min-w-0 text-sm">
                    <p>
                      <span className="font-semibold">{rule.title}</span>{" "}
                      <span className="text-muted">
                        ({label(rule.dimension, DIMENSION_LABEL)}, {rule.stage})
                      </span>
                    </p>
                    <p className="break-words text-muted">{rule.summary}</p>
                    {rule.evidence.length > 0 && (
                      <p className="code mt-0.5 text-muted">
                        {rule.evidence.map((location) => formatLocation(location)).join(", ")}
                      </p>
                    )}
                    {rule.error && (
                      <p className="sev-critical mt-1 font-semibold">
                        Rule error, excluded from scoring: <span className="code">{rule.error}</span>
                      </p>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </section>
  );
}

// --------------------------------------------------------------------- summary

function SummaryFooter({ report }: { report: AuditReport }) {
  const { summary, tool } = report;
  const facts: [string, string][] = [
    ["Rules run", String(summary.rules_run)],
    ["Passed", String(summary.rules_passed)],
    ["Failed", String(summary.rules_failed)],
    ["Not applicable", String(summary.rules_not_applicable)],
    ["Files scanned", String(summary.files_scanned)],
    ["Commits analyzed", String(summary.commits_analyzed)],
    ["Suppressed", String(summary.suppressed)],
    ["Duration", formatDuration(summary.duration_ms)],
  ];
  return (
    <footer aria-labelledby="summary-title">
      <SectionTitle id="summary-title">Summary</SectionTitle>
      <ul className="mb-4 flex flex-wrap gap-x-6 gap-y-2" aria-label="Findings by severity">
        {SEVERITIES.map((s) => (
          <li key={s}>
            <SeverityBadge severity={s} count={summary.counts_by_severity[s] ?? 0} />
          </li>
        ))}
      </ul>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
        {facts.map(([name, value]) => (
          <div key={name}>
            <dt className="narrow text-sm">{name}</dt>
            <dd className="text-lg font-bold">{value}</dd>
          </div>
        ))}
      </dl>
      {report.suppressed.length > 0 && (
        <details className="mt-4 text-sm">
          <summary className="cursor-pointer font-semibold">
            Suppressed by the baseline ({report.suppressed.length})
          </summary>
          <ul className="mt-2 border-t border-line">
            {report.suppressed.map((s) => (
              <li key={s.fingerprint} className="border-b border-line py-2">
                <span className="code font-semibold">{s.rule_id}</span>{" "}
                <span className="code text-muted">{s.path}</span>
                <p className="text-muted">{s.justification}</p>
              </li>
            ))}
          </ul>
        </details>
      )}
      <p className="mt-4 text-sm text-muted">
        {tool.name} {tool.version}, report schema {tool.schema_version}
      </p>
    </footer>
  );
}
