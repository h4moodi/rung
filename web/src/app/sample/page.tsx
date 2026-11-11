import type { Metadata } from "next";
import { ReportView } from "@/components/ReportView";
import type { AuditReport } from "@/lib/types";
import sample from "../../../public/sample-report.json";

export const metadata: Metadata = { title: "Sample report" };

export default function SamplePage() {
  const report = sample as unknown as AuditReport;
  return (
    <>
      <p className="mb-6 border-l-4 border-accent bg-surface px-4 py-2 text-sm">
        This is a bundled sample report. It needs no API and no repository.
      </p>
      <ReportView report={report} storageKey="sample" />
    </>
  );
}
