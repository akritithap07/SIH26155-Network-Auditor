import { useEffect, useRef, useState } from "react";
import {
  auditConfiguration,
  downloadAuditReport,
} from "./services/api";

function formatScore(score) {
  if (typeof score !== "number") {
    return "—";
  }

  return `${Math.round(score * 100)}%`;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) {
    return "—";
  }

  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(2)} KB`;
  }

  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function statusClass(status) {
  if (status === "PASS") {
    return "finding-status pass";
  }

  if (status === "FAIL") {
    return "finding-status fail";
  }

  return "finding-status not-assessed";
}

function severityClass(severity) {
  if (severity === "critical") {
    return "shadow-severity critical";
  }

  return "shadow-severity medium";
}

function App() {
  const fileInputRef = useRef(null);

  const [selectedFile, setSelectedFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [isDragging, setIsDragging] = useState(false);

  const [theme, setTheme] = useState(() => {
    const savedTheme = localStorage.getItem("nsc-theme");

    if (savedTheme === "dark" || savedTheme === "light") {
      return savedTheme;
    }

    return window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
  });

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("nsc-theme", theme);
  }, [theme]);

  const handleFile = (file) => {
    setError("");
    setResult(null);

    if (!file) {
      return;
    }

    setSelectedFile(file);
  };

  const handleFileInput = (event) => {
    const file = event.target.files?.[0];

    if (file) {
      handleFile(file);
    }

    event.target.value = "";
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setIsDragging(false);

    const file = event.dataTransfer.files?.[0];

    if (file) {
      handleFile(file);
    }
  };

  const handleAudit = async () => {
    if (!selectedFile) {
      setError("Please select a configuration file first.");
      return;
    }

    setIsUploading(true);
    setError("");
    setResult(null);

    try {
      const data = await auditConfiguration(selectedFile);
      setResult(data);
    } catch (auditError) {
      console.error("Configuration audit failed:", auditError);

      setError(
        auditError.message || "Unable to audit configuration.",
      );
    } finally {
      setIsUploading(false);
    }
  };

  const handleDownloadReport = async () => {
    if (!result) {
      return;
    }

    setIsGeneratingReport(true);
    setError("");

    try {
      await downloadAuditReport(result);
    } catch (reportError) {
      console.error("PDF report generation failed:", reportError);

      setError(
        reportError.message ||
          "Unable to generate the PDF report.",
      );
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const resetAnalysis = () => {
    setSelectedFile(null);
    setResult(null);
    setError("");
  };

  const detection = result?.detection;
  const compliance = result?.compliance;
  const aiAssistance = result?.ai_assistance;
  const shadowRules = result?.shadow_rules;

  const findings = compliance?.findings || [];
  const shadowIssues = shadowRules?.issues || [];

  const vendorName =
    detection?.vendor === "cisco_ios"
      ? "Cisco IOS"
      : detection?.vendor === "pfsense"
        ? "pfSense"
        : "Unknown Vendor";

  const postureScore = compliance?.summary?.posture_score ?? "—";

  return (
    <main className="app-shell">
      <div className="background-orb background-orb-one" />
      <div className="background-orb background-orb-two" />

      <section className="hero">
        <header className="topbar">
          <div className="brand-block">
            <div className="brand-mark">SIH</div>

            <div>
              <strong>Network Security</strong>
              <span>Compliance Engine</span>
            </div>
          </div>

          <button
            className="theme-toggle"
            type="button"
            onClick={() =>
              setTheme((current) =>
                current === "dark" ? "light" : "dark",
              )
            }
            aria-label={`Switch to ${
              theme === "dark" ? "light" : "dark"
            } mode`}
            title={`Switch to ${
              theme === "dark" ? "light" : "dark"
            } mode`}
          >
            <span className="theme-toggle-icon">
              {theme === "dark" ? "☀" : "☾"}
            </span>

            <span>
              {theme === "dark" ? "Light mode" : "Dark mode"}
            </span>
          </button>
        </header>

        <div className="hero-intro">
          <div className="eyebrow">SIH26155 · SECURITY AUDITOR</div>

          <h1>
            Network Security
            <span>Compliance Engine</span>
          </h1>

          <p className="hero-description">
            AI-assisted, vendor-agnostic network configuration
            security auditing with evidence, remediation, and
            rule-order analysis.
          </p>
        </div>

        <div
          className={`upload-card ${isDragging ? "dragging" : ""}`}
          onDragOver={(event) => {
            event.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
        >
          <div className="upload-icon">↑</div>

          <div className="upload-copy">
            <span className="section-kicker">CONFIGURATION INPUT</span>

            <h2>
              {isDragging
                ? "Drop your configuration here"
                : "Upload a configuration"}
            </h2>

            <p>
              Cisco IOS and pfSense configuration files are
              supported.
            </p>
          </div>

          <button
            className="primary-button"
            type="button"
            onClick={() => fileInputRef.current?.click()}
          >
            Choose File
          </button>

          <input
            ref={fileInputRef}
            type="file"
            hidden
            accept=".cfg,.conf,.txt,.xml"
            onChange={handleFileInput}
          />

          <div className="drop-hint">
            Drag and drop here, or choose a file from your
            computer
          </div>
        </div>

        {selectedFile && (
          <section className="file-card">
            <div className="file-identity">
              <div className="file-icon">CFG</div>

              <div>
                <span className="label">
                  Selected configuration
                </span>

                <strong>{selectedFile.name}</strong>

                <span className="file-meta">
                  {formatBytes(selectedFile.size)} · Ready for
                  analysis
                </span>
              </div>
            </div>

            <button
              className="secondary-button analyze-button"
              type="button"
              onClick={handleAudit}
              disabled={isUploading}
            >
              {isUploading ? (
                <>
                  <span className="spinner" />
                  Analyzing...
                </>
              ) : (
                "Analyze Configuration"
              )}
            </button>
          </section>
        )}

        {error && (
          <section
            className="message-card error-card"
            role="alert"
          >
            <div className="message-icon">!</div>

            <div>
              <strong>Something went wrong</strong>
              <p>{error}</p>
            </div>
          </section>
        )}

        {result && detection && (
          <>
            <section className="result-card detection-card">
              <div className="section-heading">
                <div>
                  <span className="section-kicker">
                    VENDOR DETECTION
                  </span>

                  <h2>{vendorName}</h2>

                  <p className="section-subtitle">
                    Configuration successfully analyzed.
                  </p>
                </div>

                <div className="status-badge success">
                  <span className="status-dot" />
                  {result.status}
                </div>
              </div>

              <div className="result-grid">
                <div className="result-item">
                  <span>Detection confidence</span>
                  <strong>
                    {detection.confidence || "Unknown"}
                  </strong>
                </div>

                <div className="result-item">
                  <span>Configuration lines</span>
                  <strong>
                    {result.line_count ?? "—"}
                  </strong>
                </div>

                <div className="result-item">
                  <span>File size</span>
                  <strong>
                    {formatBytes(result.size_bytes)}
                  </strong>
                </div>
              </div>

              <div className="detail-block">
                <div className="detail-title">
                  Detection signals
                </div>

                {detection.signals?.length ? (
                  <div className="signals">
                    {detection.signals.map((signal) => (
                      <span className="signal" key={signal}>
                        {signal}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="muted">
                    No recognized vendor signals were found.
                  </p>
                )}
              </div>

              {detection.scores && (
                <div className="score-section">
                  <div className="detail-title">
                    Detection scores
                  </div>

                  <div className="score-row">
                    <span>Cisco IOS</span>
                    <div className="score-track">
                      <div
                        className="score-fill cisco"
                        style={{
                          width: `${Math.min(
                            100,
                            Number(detection.scores.cisco_ios) *
                              10,
                          )}%`,
                        }}
                      />
                    </div>
                    <strong>
                      {detection.scores.cisco_ios}
                    </strong>
                  </div>

                  <div className="score-row">
                    <span>pfSense</span>
                    <div className="score-track">
                      <div
                        className="score-fill pfsense"
                        style={{
                          width: `${Math.min(
                            100,
                            Number(detection.scores.pfsense) *
                              10,
                          )}%`,
                        }}
                      />
                    </div>
                    <strong>
                      {detection.scores.pfsense}
                    </strong>
                  </div>
                </div>
              )}
            </section>

            {compliance && (
              <section className="result-card compliance-card">
                <div className="section-heading">
                  <div>
                    <span className="section-kicker">
                      COMPLIANCE ASSESSMENT
                    </span>

                    <h2>Security Findings</h2>

                    <p className="section-subtitle">
                      Evidence-based control assessment for the
                      uploaded configuration.
                    </p>
                  </div>

                  <div className="posture-score">
                    <span>POSTURE SCORE</span>
                    <strong>{postureScore}</strong>
                  </div>
                </div>

                <div className="compliance-summary">
                  <div className="summary-pill pass">
                    <div>
                      <span>PASS</span>
                      <strong>
                        {compliance.summary?.PASS ?? 0}
                      </strong>
                    </div>
                  </div>

                  <div className="summary-pill fail">
                    <div>
                      <span>FAIL</span>
                      <strong>
                        {compliance.summary?.FAIL ?? 0}
                      </strong>
                    </div>
                  </div>

                  <div className="summary-pill not-assessed">
                    <div>
                      <span>NOT ASSESSED</span>
                      <strong>
                        {compliance.summary?.NOT_ASSESSED ?? 0}
                      </strong>
                    </div>
                  </div>
                </div>

                <div className="findings-header">
                  <span>CONTROL FINDINGS</span>
                  <span>{findings.length} controls</span>
                </div>

                <div className="findings-list">
                  {findings.map((finding) => (
                    <article
                      className="finding-card"
                      key={finding.id}
                    >
                      <div className="finding-top">
                        <div className="finding-title-block">
                          <span className="finding-id">
                            {finding.id}
                          </span>

                          <h3>{finding.name}</h3>
                        </div>

                        <span
                          className={statusClass(
                            finding.status,
                          )}
                        >
                          {finding.status}
                        </span>
                      </div>

                      <div className="finding-meta">
                        <span>
                          Severity: {finding.severity}
                        </span>

                        <span>
                          Theme: {finding.cis_theme}
                        </span>
                      </div>

                      <p className="finding-description">
                        {finding.description}
                      </p>

                      <div className="finding-evidence-grid">
                        <div className="evidence-box">
                          <strong>Evidence</strong>
                          <span>{finding.evidence}</span>
                        </div>

                        <div className="remediation-box">
                          <strong>Remediation</strong>
                          <code>
                            {finding.remediation || "Review configuration"}
                          </code>
                        </div>
                      </div>
                    </article>
                  ))}
                </div>
              </section>
            )}

            {shadowRules && (
              <section className="result-card shadow-card">
                <div className="section-heading">
                  <div>
                    <span className="section-kicker">
                      RULE ANALYSIS
                    </span>

                    <h2>Shadow Rule Detection</h2>

                    <p className="section-subtitle">
                      Rule-order problems are reported separately
                      from compliance scoring.
                    </p>
                  </div>

                  <span className="issue-count">
                    {shadowRules.summary?.total ?? 0}{" "}
                    {(shadowRules.summary?.total ?? 0) === 1
                      ? "issue"
                      : "issues"}
                  </span>
                </div>

                <div className="shadow-disclaimer">
                  <strong>Separate from compliance</strong>
                  <span>
                    Shadow findings do not change PASS, FAIL, or
                    NOT_ASSESSED results.
                  </span>
                </div>

                <div className="shadow-summary">
                  <div className="shadow-summary-item critical">
                    <span>CRITICAL</span>
                    <strong>
                      {shadowRules.summary?.critical ?? 0}
                    </strong>
                  </div>

                  <div className="shadow-summary-item medium">
                    <span>MEDIUM</span>
                    <strong>
                      {shadowRules.summary?.medium ?? 0}
                    </strong>
                  </div>

                  <div className="shadow-summary-item neutral">
                    <span>TOTAL</span>
                    <strong>
                      {shadowRules.summary?.total ?? 0}
                    </strong>
                  </div>
                </div>

                {!shadowIssues.length ? (
                  <div className="shadow-empty">
                    <span className="empty-check">✓</span>
                    No shadowed or redundant firewall rules
                    were detected.
                  </div>
                ) : (
                  <div className="shadow-list">
                    {shadowIssues.map((issue, index) => (
                      <article
                        className="shadow-issue"
                        key={`${issue.type}-${issue.shadowed_sequence}-${index}`}
                      >
                        <div className="shadow-issue-header">
                          <div className="shadow-label-group">
                            <span
                              className={severityClass(
                                issue.severity,
                              )}
                            >
                              {issue.severity}
                            </span>

                            <span className="shadow-type">
                              {issue.type === "shadowed_deny"
                                ? "Shadowed DENY"
                                : "Redundant ALLOW"}
                            </span>
                          </div>

                          <span className="shadow-sequence">
                            Rule {issue.shadowed_sequence}
                          </span>
                        </div>

                        <h3>{issue.shadowed_rule}</h3>

                        <p className="shadow-reason">
                          {issue.reason}
                        </p>

                        <div className="shadow-details">
                          <div>
                            <span>Shadowing rule</span>
                            <strong>
                              {issue.shadowing_rule}
                            </strong>
                          </div>

                          <div>
                            <span>Shadowed rule</span>
                            <strong>
                              {issue.shadowed_rule}
                            </strong>
                          </div>
                        </div>

                        <div className="remediation-box">
                          <strong>Remediation</strong>
                          <span>{issue.remediation}</span>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </section>
            )}

            {aiAssistance && (
              <section className="result-card ai-card">
                <div className="section-heading">
                  <div>
                    <span className="section-kicker">
                      AI ASSISTANCE
                    </span>

                    <h2>Unknown Configuration Mapping</h2>

                    <p className="section-subtitle">
                      AI suggestions are advisory and never
                      override compliance decisions.
                    </p>
                  </div>

                  <span
                    className={`ai-status ${aiAssistance.status}`}
                  >
                    {aiAssistance.status}
                  </span>
                </div>

                <div className="ai-disclaimer">
                  <strong>Advisory only</strong>
                  <span>
                    AI suggestions do not change PASS, FAIL, or
                    NOT_ASSESSED compliance decisions.
                  </span>
                </div>

                {!aiAssistance.entries?.length ? (
                  <div className="ai-empty">
                    <span className="empty-check">✓</span>

                    <div>
                      <strong>No AI mapping required</strong>
                      <p>
                        No unrecognized configuration entries
                        required AI assistance.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="ai-entry-list">
                    {aiAssistance.entries.map(
                      (entry, index) => (
                        <article
                          className="ai-entry"
                          key={`${entry.line_number}-${index}`}
                        >
                          <div className="ai-entry-header">
                            <span className="label">
                              Unknown entry
                            </span>

                            <code className="unknown-line">
                              {entry.text}
                            </code>

                            {entry.context && (
                              <span className="ai-context">
                                Context: {entry.context}
                              </span>
                            )}
                          </div>

                          {entry.suggestions?.length ? (
                            <div className="ai-suggestions">
                              {entry.suggestions.map(
                                (
                                  suggestion,
                                  suggestionIndex,
                                ) => (
                                  <div
                                    className="ai-suggestion"
                                    key={`${suggestion.control_id}-${suggestionIndex}`}
                                  >
                                    <div className="suggestion-main">
                                      <div>
                                        <span className="suggestion-control">
                                          {suggestion.control_id}
                                        </span>

                                        <strong>
                                          {
                                            suggestion.target_key
                                          }
                                        </strong>
                                      </div>

                                      <span className="confidence-badge">
                                        {
                                          suggestion.confidence_band
                                        }
                                      </span>
                                    </div>

                                    <div className="suggestion-details">
                                      <span>
                                        Score:{" "}
                                        {formatScore(
                                          suggestion.score,
                                        )}
                                      </span>

                                      <span>
                                        Source:{" "}
                                        {
                                          suggestion.match_source
                                        }
                                      </span>

                                      <span>
                                        {suggestion.learned
                                          ? "Learned mapping"
                                          : "Seed knowledge"}
                                      </span>
                                    </div>

                                    <p>
                                      {
                                        suggestion.description
                                      }
                                    </p>
                                  </div>
                                ),
                              )}
                            </div>
                          ) : (
                            <p className="muted">
                              No AI mapping candidate was
                              generated for this entry.
                            </p>
                          )}
                        </article>
                      ),
                    )}
                  </div>
                )}

                <div className="ai-impact">
                  <span>Impact on compliance</span>
                  <strong>
                    {aiAssistance.impact_on_compliance}
                  </strong>
                </div>
              </section>
            )}

            <div className="action-row">
              <button
                className="primary-button"
                type="button"
                onClick={handleDownloadReport}
                disabled={isGeneratingReport}
              >
                {isGeneratingReport ? (
                  <>
                    <span className="spinner" />
                    Generating PDF...
                  </>
                ) : (
                  "Download PDF Report"
                )}
              </button>

              <button
                className="secondary-button"
                type="button"
                onClick={resetAnalysis}
              >
                Analyze Another Configuration
              </button>
            </div>
          </>
        )}
      </section>
    </main>
  );
}

export default App;