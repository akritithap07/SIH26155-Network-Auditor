import { useRef, useState } from "react";
import { uploadConfiguration } from "./services/api";

function App() {
  const fileInputRef = useRef(null);

  const [selectedFile, setSelectedFile] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isUploading, setIsUploading] = useState(false);
  const [isDragging, setIsDragging] = useState(false);

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

  const handleUpload = async () => {
    if (!selectedFile) {
      setError("Please select a configuration file first.");
      return;
    }

    setIsUploading(true);
    setError("");
    setResult(null);

    try {
      const data = await uploadConfiguration(selectedFile);
      setResult(data);
    } catch (uploadError) {
      console.error("Configuration upload failed:", uploadError);
      setError(uploadError.message || "Unable to upload configuration.");
    } finally {
      setIsUploading(false);
    }
  };

  const resetAnalysis = () => {
    setSelectedFile(null);
    setResult(null);
    setError("");
  };

  return (
    <main className="app-shell">
      <section className="hero">
        <div className="eyebrow">SIH26155</div>

        <h1>Network Security Compliance Engine</h1>

        <p className="hero-description">
          AI-assisted, vendor-agnostic network configuration security auditing.
        </p>

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

          <h2>
            {isDragging
              ? "Drop your configuration here"
              : "Upload a configuration"}
          </h2>

          <p>
            Cisco IOS or pfSense configuration files are supported in this
            phase.
          </p>

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
            onChange={handleFileInput}
          />

          <div className="drop-hint">or drag and drop your file here</div>
        </div>

        {selectedFile && (
          <section className="file-card">
            <div>
              <span className="label">Selected configuration</span>
              <strong>{selectedFile.name}</strong>

              <span className="file-meta">
                {(selectedFile.size / 1024).toFixed(2)} KB
              </span>
            </div>

            <button
              className="secondary-button"
              type="button"
              onClick={handleUpload}
              disabled={isUploading}
            >
              {isUploading ? "Analyzing..." : "Analyze Configuration"}
            </button>
          </section>
        )}

        {error && (
          <section className="message-card error-card">
            <strong>Upload failed</strong>
            <p>{error}</p>
          </section>
        )}

        {result && (
          <section className="result-card">
            <div className="result-header">
              <div>
                <span className="label">Vendor detection</span>
                <h2>
                  {result.vendor === "cisco_ios"
                    ? "Cisco IOS"
                    : result.vendor === "pfsense"
                      ? "pfSense"
                      : "Unknown Vendor"}
                </h2>
              </div>

              <div
                className={`status-badge ${
                  result.status === "detected" ? "success" : "warning"
                }`}
              >
                {result.status}
              </div>
            </div>

            <div className="result-grid">
              <div className="result-item">
                <span>Confidence</span>
                <strong>{result.confidence}</strong>
              </div>

              <div className="result-item">
                <span>Lines</span>
                <strong>{result.line_count}</strong>
              </div>

              <div className="result-item">
                <span>File size</span>
                <strong>
                  {(result.size_bytes / 1024).toFixed(2)} KB
                </strong>
              </div>
            </div>

            <div className="signals-section">
              <span className="label">Detection signals</span>

              {result.signals?.length ? (
                <div className="signals">
                  {result.signals.map((signal) => (
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

            {result.scores && (
              <div className="scores-section">
                <span className="label">Detection scores</span>

                <div className="score-row">
                  <span>Cisco IOS</span>
                  <strong>{result.scores.cisco_ios}</strong>
                </div>

                <div className="score-row">
                  <span>pfSense</span>
                  <strong>{result.scores.pfsense}</strong>
                </div>
              </div>
            )}

            <button
              className="secondary-button full-width"
              type="button"
              onClick={resetAnalysis}
            >
              Analyze Another Configuration
            </button>
          </section>
        )}
      </section>
    </main>
  );
}

export default App;