import type { Metadata } from "next";
import { Suspense } from "react";
import { Loading } from "@/components/ui";
import { AuditLoader } from "@/components/AuditLoader";

export const metadata: Metadata = { title: "Audit report" };

export default function AuditPage() {
  return (
    <Suspense fallback={<Loading label="Loading audit" />}>
      <AuditLoader />
    </Suspense>
  );
}
