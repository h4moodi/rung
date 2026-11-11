import type { Metadata } from "next";
import Link from "next/link";
import "@fontsource-variable/archivo/wdth.css";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "rung", template: "%s | rung" },
  description:
    "Stage-aware repository auditing: find which rung of the start-up progression model a repo has reached and what it takes to climb.",
};

const NAV = [
  { href: "/", label: "Audit" },
  { href: "/sample", label: "Sample report" },
  { href: "/rules", label: "Rules" },
  { href: "/stages", label: "Stages" },
];

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body className="min-h-screen flex flex-col antialiased">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:bg-surface focus:px-3 focus:py-2"
        >
          Skip to content
        </a>
        <header className="border-b-2 border-ink">
          <div className="mx-auto flex w-full max-w-6xl flex-wrap items-center justify-between gap-x-6 gap-y-1 px-4 py-3">
            <Link href="/" className="wide text-2xl no-underline" aria-label="rung home">
              rung
            </Link>
            <nav aria-label="Main">
              <ul className="flex flex-wrap gap-x-5 gap-y-1 text-sm">
                {NAV.map((item) => (
                  <li key={item.href}>
                    <Link href={item.href} className="underline-offset-4 hover:underline font-semibold">
                      {item.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </nav>
          </div>
        </header>
        <main id="main" className="mx-auto w-full max-w-6xl flex-1 px-4 py-8">
          {children}
        </main>
        <footer className="border-t border-line">
          <p className="mx-auto w-full max-w-6xl px-4 py-4 text-sm text-muted">
            rung reads repositories and never writes to them. Stages follow the start-up progression
            model of Klotins et al. (2021).
          </p>
        </footer>
      </body>
    </html>
  );
}
