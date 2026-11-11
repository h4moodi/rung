import type { Metadata } from "next";
import { StageGuide } from "@/components/Catalogue";

export const metadata: Metadata = { title: "Stages" };

export default function StagesPage() {
  return (
    <>
      <h1 className="wide text-4xl">Stages</h1>
      <p className="mb-8 mt-3 max-w-prose text-lg">
        The four rungs of the start-up progression model, and what rung expects of a repository on
        each one.
      </p>
      <StageGuide />
    </>
  );
}
