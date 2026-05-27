import Link from "next/link";

export default function LoginPage() {
  return (
    <main className="auth-shell">
      <Link className="wordmark auth-mark" href="/">
        BALONCORE
      </Link>
      <section className="auth-card">
        <span className="eyebrow">Secure access</span>
        <h1>Enter the proof console</h1>
        <form>
          <label htmlFor="email">Work email</label>
          <input id="email" defaultValue="security@company.com" />
          <label htmlFor="password">Password</label>
          <input id="password" defaultValue="baloncore-local-demo" type="password" />
          <Link className="primary-action full-action" href="/dashboard">
            Continue as customer
          </Link>
          <Link className="secondary-action full-action" href="/admin">
            Continue as admin
          </Link>
        </form>
      </section>
    </main>
  );
}
