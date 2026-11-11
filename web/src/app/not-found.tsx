import Link from "next/link";

export default function NotFound() {
  return (
    <>
      <h1 className="wide text-4xl">No such page</h1>
      <p className="mt-3">
        <Link href="/" className="underline underline-offset-4">Back to the audit form</Link>
      </p>
    </>
  );
}
