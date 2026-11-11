import Link from "next/link";
import { AuditForm } from "@/components/AuditForm";
import { RecentAudits } from "@/components/RecentAudits";

export default function HomePage() {
  return (
    <div className="flex flex-col gap-12">
      <section aria-labelledby="home-title" className="max-w-3xl">
        <h1 id="home-title" className="wide text-4xl sm:text-5xl">
          Which rung is your repository on?
        </h1>
        <p className="mt-4 max-w-prose text-lg">
          rung reads a repository&apos;s commits, containers, tests, CI, docs and security hygiene and
          places it on a four-stage ladder: inception, stabilization, growth, maturity. It then lists
          what to fix to climb one rung, and keeps quiet about practices your stage does not need yet.
        </p>
        <AuditForm />
        <p className="mt-4 text-sm">
          <Link href="/sample" className="font-semibold underline underline-offset-4">
            View sample report
          </Link>
        </p>
      </section>
      <RecentAudits />
    </div>
  );
}
