"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { ApiError, describeError, getAudit, isUnreachable, isValidAuditId } from "@/lib/api";
import type { AuditRecord } from "@/lib/types";
import { ReportView } from "./ReportView";
import { ApiDown, Loading, Notice } from "./ui";

type State =
  | { status: "loading" }
  | { status: "ready"; record: AuditRecord }
  | { status: "error"; error: unknown };

export function AuditLoader() {
  const params = useParams<{ id: string }>();
  const id = params?.id;
  const valid = isValidAuditId(id);
  const [state, setState] = useState<State>({ status: "loading" });

  useEffect(() => {
    if (!valid) return;
    const controller = new AbortController();
    getAudit(id, controller.signal)
      .then((record) => setState({ status: "ready", record }))
      .catch((error: unknown) => {
        if (!controller.signal.aborted) setState({ status: "error", error });
      });
    return () => controller.abort();
  }, [id, valid]);

  if (!valid) {
    return (
      <Notice tone="error" title="That audit id is not valid.">
        <Link href="/" className="underline">Back to the audit form</Link>
      </Notice>
    );
  }
  if (state.status === "loading") return <Loading label="Loading audit" />;
  if (state.status === "error") {
    if (isUnreachable(state.error)) return <ApiDown />;
    const missing = state.error instanceof ApiError && state.error.status === 404;
    return (
      <Notice tone="error" title={missing ? "No audit with this id." : "The audit could not be loaded."}>
        {!missing && <p>{describeError(state.error)}</p>}
        <Link href="/" className="underline">Back to the audit form</Link>
      </Notice>
    );
  }
  return <ReportView report={state.record.report} auditId={id} storageKey={id} />;
}
