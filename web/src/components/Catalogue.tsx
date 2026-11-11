"use client";

import { useEffect, useState } from "react";
import { describeError, getRules, getStages, isUnreachable } from "@/lib/api";
import { DIMENSION_LABEL, capitalize, label } from "@/lib/format";
import { DIMENSIONS, STAGES } from "@/lib/types";
import type { RuleInfo, Stage, StageInfo } from "@/lib/types";
import { ApiDown, Loading, Notice, SeverityBadge, StageBadge } from "./ui";

type State<T> = { status: "loading" } | { status: "ready"; data: T } | { status: "error"; error: unknown };

function useApi<T>(load: (signal: AbortSignal) => Promise<T>): State<T> {
  const [state, setState] = useState<State<T>>({ status: "loading" });
  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal)
      .then((data) => setState({ status: "ready", data }))
      .catch((error: unknown) => {
        if (!controller.signal.aborted) setState({ status: "error", error });
      });
    return () => controller.abort();
  }, [load]);
  return state;
}

function Failure({ error, what }: { error: unknown; what: string }) {
  if (isUnreachable(error)) return <ApiDown />;
  return (
    <Notice tone="error" title={`${what} could not be loaded.`}>
      {describeError(error)}
    </Notice>
  );
}

export function RuleCatalogue() {
  const state = useApi<RuleInfo[]>(getRules);
  const [stage, setStage] = useState<Stage | "all">("all");

  if (state.status === "loading") return <Loading label="Loading rules" />;
  if (state.status === "error") return <Failure error={state.error} what="The rule catalogue" />;
  const rules = stage === "all" ? state.data : state.data.filter((r) => r.stage === stage);
  const known = new Set<string>(DIMENSIONS);
  const groups = [...DIMENSIONS, ...new Set(state.data.map((r) => r.dimension).filter((d) => !known.has(d)))];

  return (
    <>
      <label className="mb-6 flex max-w-xs flex-col gap-1 text-sm" htmlFor="stage-filter">
        <span className="narrow">Expected from stage</span>
        <select
          id="stage-filter"
          className="field"
          value={stage}
          onChange={(e) => setStage(e.target.value as Stage | "all")}
        >
          <option value="all">All stages ({state.data.length})</option>
          {STAGES.map((s) => (
            <option key={s} value={s}>{capitalize(s)}</option>
          ))}
        </select>
      </label>
      {rules.length === 0 && <p className="text-muted">No rules for this stage.</p>}
      <div className="flex flex-col gap-10">
        {groups.map((dimension) => {
          const own = rules.filter((r) => r.dimension === dimension);
          if (own.length === 0) return null;
          return (
            <section key={dimension} aria-label={label(dimension, DIMENSION_LABEL)}>
              <h2 className="wide border-b-2 border-ink pb-2 text-xl">
                {label(dimension, DIMENSION_LABEL)}{" "}
                <span className="text-base font-normal text-muted">({own.length})</span>
              </h2>
              <ul>
                {own.map((rule) => (
                  <li key={rule.id} className="grid gap-x-4 gap-y-1 border-b border-line py-3 sm:grid-cols-[5rem_1fr]">
                    <span className="code font-semibold">{rule.id}</span>
                    <div className="min-w-0">
                      <p className="font-semibold">{rule.title}</p>
                      <p className="max-w-prose text-sm">{rule.description}</p>
                      <p className="mt-1 max-w-prose text-sm text-muted">Fix: {rule.remediation}</p>
                      <p className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted">
                        <StageBadge stage={rule.stage} />
                        <SeverityBadge severity={rule.severity} />
                        <span>Confidence: {rule.confidence}</span>
                        <span>Weight: {rule.weight}</span>
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            </section>
          );
        })}
      </div>
    </>
  );
}

export function StageGuide() {
  const state = useApi<StageInfo[]>(getStages);
  if (state.status === "loading") return <Loading label="Loading stages" />;
  if (state.status === "error") return <Failure error={state.error} what="The stage guide" />;
  if (state.data.length === 0) return <p className="text-muted">The API returned no stages.</p>;
  const stages = [...state.data].sort((a, b) => STAGES.indexOf(b.stage) - STAGES.indexOf(a.stage));
  return (
    <ol className="max-w-3xl border-l-[10px] border-ink" aria-label="Stages, highest rung first">
      {stages.map((info) => (
        <li key={info.stage} className="border-t-2 border-ink py-5 pl-5">
          <h2 className="wide text-2xl">{info.title}</h2>
          <p className="mt-1 max-w-prose">{info.summary}</p>
          <ul className="mt-2 list-disc pl-5 text-sm">
            {info.expectations.map((expectation) => (
              <li key={expectation}>{expectation}</li>
            ))}
          </ul>
        </li>
      ))}
    </ol>
  );
}
