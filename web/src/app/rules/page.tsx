import type { Metadata } from "next";
import { RuleCatalogue } from "@/components/Catalogue";

export const metadata: Metadata = { title: "Rules" };

export default function RulesPage() {
  return (
    <>
      <h1 className="wide text-4xl">Rules</h1>
      <p className="mb-8 mt-3 max-w-prose text-lg">
        Every check rung runs, grouped by the artifact it inspects. A rule&apos;s stage is the rung
        from which the practice is expected.
      </p>
      <RuleCatalogue />
    </>
  );
}
