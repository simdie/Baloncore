import Link from "next/link";

const metrics = [
  ["5", "proof lanes"],
  ["90", "latest proof score"],
  ["45", "artifacts per API proof"],
  ["127.0.0.1", "local safe default"],
];

const outcomes = [
  "Exploitability proof before report",
  "False-positive kill checks",
  "Signed evidence bundles",
  "Regression replay after fixes",
  "Defense rule packs",
  "Defense rules from the same proof",
];

const modules = [
  {
    name: "API and Web App Proof",
    text: "Authorization matrixing, BOLA/BFLA classification, missing-auth gates, response-shape analysis, and sensitive-field impact ranking.",
  },
  {
    name: "Cloud and IAM Attack Paths",
    text: "Privilege edges, public exposure, risky trust relationships, Terraform and provider export analysis.",
  },
  {
    name: "Web3 Proof Forge",
    text: "Solidity project analysis, invariant generation, proof-test handoff, and protocol risk reporting.",
  },
  {
    name: "Defense Fabric",
    text: "Remediation, CI regression, SARIF, signed evidence, detection rules, and lifecycle state.",
  },
  {
    name: "Executive Proof Room",
    text: "Board-ready briefs, risk registers, policy gates, scope contracts, and sector threat models for buyers and funders.",
  },
];

export default function Home() {
  return (
    <main className="site-shell">
      <nav className="site-nav">
        <Link className="wordmark" href="/">
          BALONCORE
        </Link>
        <div className="nav-links">
          <a href="#platform">Platform</a>
          <a href="#proof">Proof</a>
          <a href="#defense">Defense</a>
          <Link href="/admin">Admin</Link>
        </div>
        <Link className="nav-cta" href="/login">
          Enter Console
        </Link>
      </nav>

      <section className="hero">
        <div className="hero-copy">
          <span className="eyebrow">Autonomous security validation</span>
          <h1>BALONCORE</h1>
          <p className="hero-lede">
            AI-speed offensive security with deterministic proof, signed evidence,
            and defense automation for teams that need real exploitability,
            not scanner noise.
          </p>
          <div className="hero-actions">
            <Link className="primary-action" href="/login">
              Start authorized test
            </Link>
            <Link className="secondary-action" href="/dashboard">
              View live product
            </Link>
          </div>
          <div className="metric-strip">
            {metrics.map(([value, label]) => (
              <div key={label}>
                <strong>{value}</strong>
                <span>{label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="hero-visual" aria-label="BALONCORE proof engine preview">
          <div className="visual-header">
            <span>Proof Twin</span>
            <strong>investor_demo_ready_local</strong>
          </div>
          <div className="attack-map">
            <div className="node node-hot">API</div>
            <div className="node">IAM</div>
            <div className="node node-proof">PROOF</div>
            <div className="node">CI</div>
            <div className="node node-safe">DEFENSE</div>
          </div>
          <div className="proof-feed">
            {outcomes.map((item, index) => (
              <div className="feed-row" key={item}>
                <span>0{index + 1}</span>
                <p>{item}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="logo-band">
        <span>Built for startups</span>
        <span>Fintech</span>
        <span>Health</span>
        <span>Web3</span>
        <span>Cloud</span>
        <span>SaaS</span>
      </section>

      <section className="section" id="platform">
        <div className="section-heading">
          <span className="eyebrow">Platform</span>
          <h2>Autonomous testing with evidence a board can trust.</h2>
        </div>
        <div className="module-grid">
          {modules.map((module) => (
            <article className="module-card" key={module.name}>
              <h3>{module.name}</h3>
              <p>{module.text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="split-section" id="proof">
        <div>
          <span className="eyebrow">Differentiation</span>
          <h2>AI can suspect. BALONCORE must prove.</h2>
          <p>
            BALONCORE turns hypotheses into validated proof packages, then turns
            each proof into replayable defense. That loop is the product moat.
          </p>
        </div>
        <div className="proof-panel">
          <div className="proof-step active">Hypothesis</div>
          <div className="proof-step active">Validation</div>
          <div className="proof-step active">Evidence</div>
          <div className="proof-step active">Regression</div>
          <div className="proof-step">Defense fabric</div>
        </div>
      </section>

      <section className="section defense-band" id="defense">
        <span className="eyebrow">Defense</span>
        <h2>Every verified issue becomes a prevention system.</h2>
        <p>
          Signed evidence, remediation, CI gates, redaction checks, detection
          rules, and lifecycle memory keep the same bug from quietly returning.
        </p>
        <Link className="primary-action" href="/dashboard">
          Open customer dashboard
        </Link>
      </section>
    </main>
  );
}
