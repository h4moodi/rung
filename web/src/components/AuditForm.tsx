"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { createAudit, describeError, isUnreachable } from "@/lib/api";
import { validateRepoUrl } from "@/lib/format";
import { ApiDown, Loading } from "./ui";

export function AuditForm() {
  const router = useRouter();
  const [source, setSource] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const [failure, setFailure] = useState<unknown>(null);
  const [running, setRunning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const controller = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!running) return;
    const started = Date.now();
    const timer = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => clearInterval(timer);
  }, [running]);

  useEffect(() => () => controller.current?.abort(), []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const invalid = validateRepoUrl(source);
    setProblem(invalid);
    setFailure(null);
    if (invalid) return;
    const abort = new AbortController();
    controller.current = abort;
    setElapsed(0);
    setRunning(true);
    try {
      const record = await createAudit(source.trim(), abort.signal);
      router.push(`/audits/${encodeURIComponent(record.id)}`);
    } catch (error) {
      if (!abort.signal.aborted) setFailure(error);
      setRunning(false);
    }
  }

  function cancel() {
    controller.current?.abort();
    setRunning(false);
  }

  return (
    <form onSubmit={submit} noValidate className="mt-6">
      <label htmlFor="source" className="narrow block text-sm">
        Repository URL
      </label>
      <div className="mt-1 flex flex-col gap-2 sm:flex-row">
        <input
          id="source"
          name="source"
          type="url"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          className="field code min-w-0 flex-1"
          placeholder="https://github.com/owner/repo"
          value={source}
          onChange={(e) => setSource(e.target.value)}
          disabled={running}
          aria-invalid={problem !== null}
          aria-describedby={problem ? "source-problem" : undefined}
        />
        <button type="submit" className="btn btn-primary" disabled={running}>
          {running ? "Auditing" : "Audit"}
        </button>
      </div>
      {problem && (
        <p id="source-problem" role="alert" className="sev-critical mt-2 text-sm font-semibold">
          {problem}
        </p>
      )}
      {running && (
        <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2">
          <Loading label={`Cloning and auditing, ${elapsed} s. Large repositories can take a couple of minutes.`} />
          <button type="button" className="btn" onClick={cancel}>
            Stop waiting
          </button>
        </div>
      )}
      {failure !== null && !running && (
        <div className="mt-4">
          {isUnreachable(failure) && (failure as { kind?: string }).kind === "network" ? (
            <ApiDown />
          ) : (
            <p role="alert" className="sev-critical border-l-4 border-current bg-surface px-4 py-3 font-semibold">
              Audit failed: {describeError(failure)}
            </p>
          )}
        </div>
      )}
    </form>
  );
}
