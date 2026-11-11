"use client";

export default function ErrorPage({ reset }: { error: Error; reset: () => void }) {
  return (
    <div role="alert">
      <h1 className="wide text-4xl">This page failed to render</h1>
      <p className="mt-3 text-muted">The report may not match the schema this dashboard expects.</p>
      <button type="button" className="btn mt-4" onClick={reset}>
        Try again
      </button>
    </div>
  );
}
