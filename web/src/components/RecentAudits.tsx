"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { describeError, isUnreachable, isValidAuditId, listAudits } from "@/lib/api";
import { formatScore, relativeTime } from "@/lib/format";
import { SEVERITIES } from "@/lib/types";
import type { AuditListItem } from "@/lib/types";
import { ApiDown, Loading, Notice, SeverityBadge, StageBadge } from "./ui";

type State =
  | { status: "loading" }
  | { status: "ready"; items: AuditListItem[]; now: number }
  | { status: "error"; error: unknown };

export function RecentAudits() {
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    listAudits(10, 0, controller.signal)
      .then((items) => setState({ status: "ready", items, now: Date.now() }))
      .catch((error: unknown) => {
        if (!controller.signal.aborted) setState({ status: "error", error });
      });
    return () => controller.abort();
  }, []);

  return (
    <section aria-labelledby="recent-title">
      <h2 id="recent-title" className="wide mb-4 border-b-2 border-ink pb-2 text-xl">
        Recent audits
      </h2>
      {state.status === "loading" && <Loading label="Loading recent audits" />}
      {state.status === "error" &&
        (isUnreachable(state.error) ? (
          <ApiDown />
        ) : (
          <Notice tone="error" title="Recent audits could not be loaded.">
            {describeError(state.error)}
          </Notice>
        ))}
      {state.status === "ready" && state.items.length === 0 && (
        <p className="text-muted">No audits yet. Enter a repository URL above to run the first one.</p>
      )}
      {state.status === "ready" && state.items.length > 0 && (
        <ul>
          {state.items.filter((item) => isValidAuditId(item.id)).map((item) => (
            <li
              key={item.id}
              className="grid gap-x-6 gap-y-1 border-b border-line py-3 sm:grid-cols-[1fr_auto_auto] sm:items-center"
            >
              <div className="min-w-0">
                <Link
                  href={`/audits/${encodeURIComponent(item.id)}`}
                  className="code break-words font-semibold underline underline-offset-4"
                >
                  {item.source}
                </Link>
                <p className="text-sm text-muted">{relativeTime(item.created_at, state.now)}</p>
              </div>
              <ul className="flex flex-wrap gap-x-3 gap-y-1" aria-label="Findings by severity">
                {SEVERITIES.filter((s) => (item.counts_by_severity?.[s] ?? 0) > 0).map((s) => (
                  <li key={s}>
                    <SeverityBadge severity={s} count={item.counts_by_severity[s]} />
                  </li>
                ))}
              </ul>
              <p className="flex items-center gap-3">
                <StageBadge stage={item.stage} />
                <span className="text-lg font-bold">{formatScore(item.overall_score)}</span>
              </p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
