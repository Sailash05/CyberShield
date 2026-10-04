import { useState } from "react";

const API_URL = "http://127.0.0.1:8000/api";

function SeverityBadge({ severity }) {
  const styles = {
    Critical: "bg-red-500/20 text-red-400 border-red-500/30",
    High: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    Medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    Low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    Informational: "bg-slate-500/20 text-slate-400 border-slate-500/30",
  };

  return (
    <span
      className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${
        styles[severity] || styles.Informational
      }`}
    >
      {severity}
    </span>
  );
}

function RiskCard({ risk }) {
  if (!risk) return null;

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <div className="mb-5 flex items-center justify-between">
        <div>
          <p className="text-sm text-slate-400">Overall Risk Score</p>
          <h2 className="mt-1 text-3xl font-bold text-white">
            {risk.risk_score}
            <span className="text-lg text-slate-500"> / 100</span>
          </h2>
        </div>

        <div className="rounded-xl bg-slate-800 px-4 py-2">
          <span className="text-sm font-semibold text-slate-300">
            {risk.risk_level}
          </span>
        </div>
      </div>

      <div className="h-3 overflow-hidden rounded-full bg-slate-800">
        <div
          className="h-full rounded-full bg-red-500 transition-all duration-700"
          style={{
            width: `${Math.min(risk.risk_score, 100)}%`,
          }}
        />
      </div>

      <div className="mt-4 flex justify-between text-xs text-slate-500">
        <span>0</span>
        <span>25</span>
        <span>50</span>
        <span>75</span>
        <span>100</span>
      </div>

      <p className="mt-4 text-sm text-slate-400">
        Raw score: {risk.raw_score}
      </p>
    </div>
  );
}

function SummaryCard({ title, value, description }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <p className="text-sm text-slate-400">{title}</p>
      <p className="mt-2 text-3xl font-bold text-white">{value}</p>
      <p className="mt-1 text-xs text-slate-500">{description}</p>
    </div>
  );
}

function FindingsTable({ findings }) {
  if (!findings || findings.length === 0) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 text-center text-slate-400">
        No findings available.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-800 bg-slate-950">
            <tr>
              <th className="px-5 py-4 font-semibold text-slate-300">
                Source
              </th>
              <th className="px-5 py-4 font-semibold text-slate-300">
                Finding
              </th>
              <th className="px-5 py-4 font-semibold text-slate-300">
                Severity
              </th>
              <th className="px-5 py-4 font-semibold text-slate-300">
                Status
              </th>
              <th className="px-5 py-4 font-semibold text-slate-300">
                Description
              </th>
            </tr>
          </thead>

          <tbody>
            {findings.map((finding, index) => (
              <tr
                key={index}
                className="border-b border-slate-800/70 hover:bg-slate-800/40"
              >
                <td className="px-5 py-4 text-slate-400">
                  {finding.source}
                </td>

                <td className="px-5 py-4 font-medium text-white">
                  {finding.title}
                </td>

                <td className="px-5 py-4">
                  <SeverityBadge severity={finding.severity} />
                </td>

                <td className="px-5 py-4 text-slate-400">
                  {finding.status || "-"}
                </td>

                <td className="max-w-md px-5 py-4 text-slate-400">
                  {finding.description || "-"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AnalysisSection({ title, data }) {
  const [open, setOpen] = useState(false);

  if (!data) return null;

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between px-5 py-4 text-left hover:bg-slate-800/50"
      >
        <span className="font-semibold text-white">{title}</span>

        <span className="text-slate-400">
          {open ? "−" : "+"}
        </span>
      </button>

      {open && (
        <div className="border-t border-slate-800 p-5">
          <pre className="overflow-x-auto rounded-lg bg-slate-950 p-4 text-xs leading-6 text-slate-300">
            {JSON.stringify(data, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function App() {
  const [url, setUrl] = useState("");
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [activeTab, setActiveTab] = useState("security");

  const [phishingUrl, setPhishingUrl] = useState("");
  const [phishingData, setPhishingData] = useState(null);
  const [phishingLoading, setPhishingLoading] = useState(false);
  const [phishingError, setPhishingError] = useState("");

  const handleScan = async (e) => {
    e.preventDefault();

    if (!url.trim()) {
      setError("Please enter a website URL.");
      return;
    }

    setLoading(true);
    setError("");
    setScanData(null);

    try {
      const response = await fetch(`${API_URL}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: url.trim(),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Scan failed.");
      }

      setScanData(data);
    } catch (err) {
      setError(
        err.message ||
          "Unable to connect to Cyber Shield API."
      );
    } finally {
      setLoading(false);
    }
  };

  const handlePhishingCheck = async (e) => {
  e.preventDefault();

  if (!phishingUrl.trim()) {
    setPhishingError("Please enter a website URL.");
    return;
  }

  setPhishingLoading(true);
  setPhishingError("");
  setPhishingData(null);

  try {
    const response = await fetch(
      `${API_URL}/legitimacy-analysis`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: phishingUrl.trim(),
        }),
      }
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        typeof data.detail === "string"
          ? data.detail
          : "Phishing analysis failed."
      );
    }

    setPhishingData(data);
  } catch (err) {
    setPhishingError(
      err.message || "Unable to connect to Cyber Shield API."
    );
  } finally {
    setPhishingLoading(false);
  }
};

  const summary = scanData?.summary;

  return (
    <div className="min-h-screen bg-slate-950">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-950/90">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-5">
          <div>
            <h1 className="text-xl font-bold tracking-wide text-white">
              CYBER<span className="text-cyan-400">SHIELD</span>
            </h1>

            <p className="text-xs text-slate-500">
              Intelligent Web Security Assessment Platform
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            <span className="text-xs text-slate-400">
              Security Engine
            </span>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
<div className="border-b border-slate-800 bg-slate-950">
  <div className="mx-auto flex max-w-7xl gap-2 px-6">
    <button
      onClick={() => setActiveTab("security")}
      className={`border-b-2 px-5 py-4 text-sm font-semibold transition ${
        activeTab === "security"
          ? "border-cyan-400 text-cyan-400"
          : "border-transparent text-slate-400 hover:text-white"
      }`}
    >
      Web Security Assessment
    </button>

    <button
      onClick={() => setActiveTab("phishing")}
      className={`border-b-2 px-5 py-4 text-sm font-semibold transition ${
        activeTab === "phishing"
          ? "border-cyan-400 text-cyan-400"
          : "border-transparent text-slate-400 hover:text-white"
      }`}
    >
      Phishing URL Detection
    </button>
  </div>
</div>

      <main className="mx-auto max-w-7xl px-6 py-10">

        {activeTab === "security" ? (
          <>
        {/* Hero */}
        <section className="mb-10">
          <div className="mb-6">
            <h2 className="text-3xl font-bold text-white md:text-4xl">
              Web Security Assessment
            </h2>

            <p className="mt-2 max-w-2xl text-slate-400">
              Analyze a website's DNS, HTTP headers, SSL/TLS,
              technologies, URL characteristics and other
              security indicators.
            </p>
          </div>

          {/* Scan Form */}
          <form
            onSubmit={handleScan}
            className="rounded-2xl border border-slate-800 bg-slate-900 p-4 shadow-xl"
          >
            <div className="flex flex-col gap-3 md:flex-row">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="flex-1 rounded-xl border border-slate-700 bg-slate-950 px-5 py-4 text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-500"
              />

              <button
                type="submit"
                disabled={loading}
                className="rounded-xl bg-cyan-500 px-8 py-4 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading ? "Scanning..." : "Start Scan"}
              </button>
            </div>

            {error && (
              <div className="mt-3 rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                {error}
              </div>
            )}
          </form>
        </section>

        {/* Loading */}
        {loading && (
          <div className="mb-8 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-6 text-center">
            <div className="mx-auto mb-3 h-8 w-8 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />

            <p className="font-medium text-cyan-400">
              Running security assessment...
            </p>

            <p className="mt-1 text-sm text-slate-500">
              Collecting and analyzing security information
            </p>
          </div>
        )}

        {/* Results */}
        {scanData && !loading && (
          <div className="space-y-8">
            {/* Target */}
            <div className="rounded-xl border border-slate-800 bg-slate-900 px-5 py-4">
              <p className="text-xs uppercase tracking-wider text-slate-500">
                Scanned Target
              </p>

              <p className="mt-1 break-all font-mono text-sm text-cyan-400">
                {scanData.target}
              </p>
            </div>

            {/* Risk */}
            <section>
              <h3 className="mb-4 text-lg font-semibold text-white">
                Security Overview
              </h3>

              <div className="grid gap-5 lg:grid-cols-3">
                <RiskCard risk={scanData.risk} />

                <div className="grid grid-cols-2 gap-4 lg:col-span-2">
                  <SummaryCard
                    title="Critical"
                    value={summary?.Critical || 0}
                    description="Critical security findings"
                  />

                  <SummaryCard
                    title="High"
                    value={summary?.High || 0}
                    description="High severity findings"
                  />

                  <SummaryCard
                    title="Medium"
                    value={summary?.Medium || 0}
                    description="Medium severity findings"
                  />

                  <SummaryCard
                    title="Low"
                    value={summary?.Low || 0}
                    description="Low severity findings"
                  />
                </div>
              </div>
            </section>

            {/* Informational */}
            <section className="grid gap-5 md:grid-cols-2">
              <SummaryCard
                title="Informational"
                value={summary?.Informational || 0}
                description="Informational observations"
              />

              <SummaryCard
                title="Total Findings"
                value={summary?.Total || 0}
                description="All analyzed findings"
              />
            </section>

            {/* Findings */}
            <section>
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <h3 className="text-lg font-semibold text-white">
                    Security Findings
                  </h3>

                  <p className="text-sm text-slate-500">
                    Findings sorted by severity
                  </p>
                </div>
              </div>

              <FindingsTable findings={scanData.findings} />
            </section>

            {/* Detailed Analysis */}
            <section>
              <div className="mb-4">
                <h3 className="text-lg font-semibold text-white">
                  Detailed Analysis
                </h3>

                <p className="text-sm text-slate-500">
                  Raw results from each security analysis module
                </p>
              </div>

              <div className="space-y-3">
                <AnalysisSection
                  title="DNS Analysis"
                  data={scanData.analysis?.dns}
                />

                <AnalysisSection
                  title="HTTP Headers"
                  data={scanData.analysis?.headers}
                />

                <AnalysisSection
                  title="HTTP Information"
                  data={scanData.analysis?.http_info}
                />

                <AnalysisSection
                  title="HTTP Methods"
                  data={scanData.analysis?.http_methods}
                />

                <AnalysisSection
                  title="SSL / TLS"
                  data={scanData.analysis?.ssl}
                />

                <AnalysisSection
                  title="Technology Detection"
                  data={scanData.analysis?.technology}
                />

                <AnalysisSection
                  title="URL Analysis"
                  data={scanData.analysis?.url}
                />

                <AnalysisSection
                  title="WHOIS Analysis"
                  data={scanData.analysis?.whois}
                />
              </div>
            </section>
          </div>
        )}

        {/* Empty state */}
        {!scanData && !loading && (
          <div className="rounded-2xl border border-dashed border-slate-800 bg-slate-900/40 p-16 text-center">
            <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-2xl bg-cyan-500/10">
              <span className="text-3xl">⌁</span>
            </div>

            <h3 className="text-lg font-semibold text-white">
              Ready to scan
            </h3>

            <p className="mx-auto mt-2 max-w-md text-sm text-slate-500">
              Enter a website URL above to start a Cyber Shield
              security assessment.
            </p>
          </div>
        )}
        
          </>
  ) : (
    /* Phishing URL Detection Page */
    <section className="mx-auto max-w-4xl">

{/* Page Heading */}
<div className="mb-8">
  <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-xs font-semibold text-cyan-400">
    Rule-Based Detection
  </div>

  <h2 className="text-3xl font-bold text-white md:text-4xl">
    Phishing Website Detection
  </h2>

  <p className="mt-3 max-w-2xl text-slate-400">
    Analyze webpage text using predefined keyword rules to
    identify potential phishing indicators and classify the
    website.
  </p>
</div>

      {/* URL Input Form */}
      <form
        onSubmit={handlePhishingCheck}
        className="rounded-2xl border border-slate-800 bg-slate-900 p-5 shadow-xl"
      >
        <label
          htmlFor="phishing-url"
          className="mb-3 block text-sm font-medium text-slate-300"
        >
          Website URL
        </label>

        <div className="flex flex-col gap-3 sm:flex-row">
          <input
            id="phishing-url"
            type="url"
            value={phishingUrl}
            onChange={(e) => setPhishingUrl(e.target.value)}
            placeholder="https://example.com"
            required
            className="min-w-0 flex-1 rounded-xl border border-slate-700 bg-slate-950 px-4 py-4 text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-500"
          />

          <button
            type="submit"
            disabled={phishingLoading}
            className="rounded-xl bg-cyan-500 px-6 py-4 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {phishingLoading ? "Analyzing..." : "Check URL"}
          </button>
        </div>

        {phishingError && (
          <div className="mt-4 rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            {phishingError}
          </div>
        )}
      </form>

      {/* Loading Indicator */}
      {phishingLoading && (
        <div className="mt-6 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-8 text-center">
          <div className="mx-auto mb-4 h-8 w-8 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />

          <p className="font-medium text-cyan-400">
            Analyzing webpage...
          </p>

          <p className="mt-2 text-sm text-slate-500">
            Retrieving webpage content and running the ML model.
          </p>
        </div>
      )}

{/* Analysis Results */}
{phishingData && !phishingLoading && (
  <div className="mt-8 space-y-5">

    {/* Classification and Risk Score */}
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
      <p className="text-sm text-slate-400">
        Website Classification
      </p>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-4">
        <h3
          className={`text-3xl font-bold ${
            phishingData.result?.classification === "Phishing"
              ? "text-red-400"
              : "text-emerald-400"
          }`}
        >
          {phishingData.result?.classification || "Unknown"}
        </h3>

        <span
          className={`rounded-full border px-4 py-2 text-sm font-semibold ${
            phishingData.result?.classification === "Phishing"
              ? "border-red-500/30 bg-red-500/10 text-red-400"
              : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
          }`}
        >
          {phishingData.result?.classification === "Phishing"
            ? "Potential Phishing"
            : "Classified as Legitimate"}
        </span>
      </div>

      {/* Heuristic Risk Score */}
      <div className="mt-8">
        <div className="mb-2 flex items-center justify-between gap-3">
          <span className="text-sm text-slate-400">
            Keyword-Based Risk Score
          </span>

          <span className="font-semibold text-white">
            {phishingData.result?.risk_score ?? 0} / 100
          </span>
        </div>

        <div className="h-3 overflow-hidden rounded-full bg-slate-800">
          <div
            className={`h-full rounded-full transition-all duration-700 ${
              phishingData.result?.classification === "Phishing"
                ? "bg-red-500"
                : "bg-emerald-500"
            }`}
            style={{
              width: `${Math.min(
                Math.max(
                  phishingData.result?.risk_score ?? 0,
                  0
                ),
                100
              )}%`,
            }}
          />
        </div>

        <p className="mt-3 text-xs leading-5 text-slate-500">
          This score is calculated from matching keyword occurrences.
          It is a heuristic score, not a probability of phishing.
        </p>
      </div>
    </div>

    {/* Analyzed URL */}
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <p className="text-sm text-slate-400">
        Analyzed URL
      </p>

      <p className="mt-2 break-all font-mono text-sm text-cyan-400">
        {phishingData.target}
      </p>

      <p className="mt-3 text-xs text-slate-500">
        Analysis method:{" "}
        {phishingData.method || "Dictionary-Based Keyword Analysis"}
      </p>
    </div>

    {/* Summary Cards */}
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">

      <div className="rounded-xl border border-red-500/20 bg-slate-900 p-5">
        <p className="text-sm text-slate-400">
          Phishing Keywords
        </p>

        <p className="mt-2 text-3xl font-bold text-red-400">
          {phishingData.result?.phishing_word_count ?? 0}
        </p>

        <p className="mt-1 text-xs text-slate-500">
          Matching word occurrences
        </p>
      </div>

      <div className="rounded-xl border border-emerald-500/20 bg-slate-900 p-5">
        <p className="text-sm text-slate-400">
          Legitimate Keywords
        </p>

        <p className="mt-2 text-3xl font-bold text-emerald-400">
          {phishingData.result?.legitimate_word_count ?? 0}
        </p>

        <p className="mt-1 text-xs text-slate-500">
          Matching word occurrences
        </p>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <p className="text-sm text-slate-400">
          Total Matches
        </p>

        <p className="mt-2 text-3xl font-bold text-white">
          {phishingData.result?.matched_word_count ?? 0}
        </p>

        <p className="mt-1 text-xs text-slate-500">
          All dictionary matches
        </p>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <p className="text-sm text-slate-400">
          Extracted Text
        </p>

        <p className="mt-2 text-3xl font-bold text-cyan-400">
          {phishingData.result?.text_length ?? 0}
        </p>

        <p className="mt-1 text-xs text-slate-500">
          Characters analyzed
        </p>
      </div>

    </div>

    {/* Matched Phishing Keywords */}
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
      <div className="border-b border-slate-800 p-5">
        <h3 className="font-semibold text-white">
          Phishing Keyword Matches
        </h3>

        <p className="mt-1 text-sm text-slate-400">
          Predefined words identified in the webpage text.
        </p>
      </div>

      {Object.keys(
        phishingData.result?.phishing_matches || {}
      ).length > 0 ? (
        <div className="flex flex-wrap gap-2 p-5">
          {Object.entries(
            phishingData.result.phishing_matches
          ).map(([word, count]) => (
            <span
              key={word}
              className="inline-flex items-center gap-2 rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-300"
            >
              <span>{word}</span>

              <span className="rounded bg-red-500/20 px-2 py-0.5 text-xs font-semibold">
                {count}
              </span>
            </span>
          ))}
        </div>
      ) : (
        <p className="p-5 text-sm text-slate-500">
          No phishing-related keywords matched.
        </p>
      )}
    </div>

    {/* Matched Legitimate Keywords */}
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
      <div className="border-b border-slate-800 p-5">
        <h3 className="font-semibold text-white">
          Legitimate Keyword Matches
        </h3>

        <p className="mt-1 text-sm text-slate-400">
          Words categorized as non-phishing indicators in your dictionary.
        </p>
      </div>

      {Object.keys(
        phishingData.result?.legitimate_matches || {}
      ).length > 0 ? (
        <div className="flex flex-wrap gap-2 p-5">
          {Object.entries(
            phishingData.result.legitimate_matches
          ).map(([word, count]) => (
            <span
              key={word}
              className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300"
            >
              <span>{word}</span>

              <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-xs font-semibold">
                {count}
              </span>
            </span>
          ))}
        </div>
      ) : (
        <p className="p-5 text-sm text-slate-500">
          No legitimate-related keywords matched.
        </p>
      )}
    </div>

    {/* Analysis Explanation */}
    <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-5">
      <h3 className="font-semibold text-cyan-400">
        Analysis Details
      </h3>

      <p className="mt-2 text-sm leading-6 text-slate-400">
        {phishingData.result?.message ||
          "Classification is based on predefined keyword matching."}
      </p>

      <p className="mt-3 text-xs leading-5 text-slate-500">
        Keyword matches are indicators, not proof of malicious
        activity. A legitimate website may contain phishing-related
        words, and a phishing website may avoid them.
      </p>
    </div>

  </div>
)}
      {/* Empty State */}
      {!phishingData && !phishingLoading && !phishingError && (
        <div className="mt-6 rounded-2xl border border-dashed border-slate-800 bg-slate-900/40 p-12 text-center">
          <div className="mb-4 text-4xl">⌕</div>

          <h3 className="font-semibold text-white">
            Ready to analyze
          </h3>

          <p className="mx-auto mt-2 max-w-md text-sm text-slate-500">
            Enter a URL to analyze its webpage text and view the
            phishing classification.
          </p>
        </div>
      )}

    </section>
  )}

</main>


      <footer className="border-t border-slate-800 py-6 text-center text-xs text-slate-600">
        Cyber Shield — Intelligent Web Security Assessment Platform
      </footer>
    </div>
  );
}

export default App;