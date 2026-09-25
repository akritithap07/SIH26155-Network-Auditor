import { useEffect, useState } from "react";

function App() {
  const [backendStatus, setBackendStatus] = useState("Checking backend...");
  const [backendHealthy, setBackendHealthy] = useState(false);

  useEffect(() => {
    const checkBackend = async () => {
      try {
        const response = await fetch("http://127.0.0.1:8000/health");

        if (!response.ok) {
          throw new Error("Backend returned an error");
        }

        const data = await response.json();

        setBackendStatus(`${data.status} — ${data.service}`);
        setBackendHealthy(true);
      } catch (error) {
        console.error("Backend health check failed:", error);
        setBackendStatus("Backend unavailable");
        setBackendHealthy(false);
      }
    };

    checkBackend();
  }, []);

  return (
    <main className="app">
      <section className="card">
        <div className="status-icon">
          {backendHealthy ? "✓" : "!"}
        </div>

        <h1>SIH26155 Network Security Compliance Engine</h1>

        <p className="subtitle">
          AI-assisted, vendor-agnostic network security configuration auditor
        </p>

        <div className="environment">
          <div>
            <span>Frontend</span>
            <strong>React + Vite</strong>
          </div>

          <div>
            <span>Backend</span>
            <strong
              className={
                backendHealthy ? "status healthy" : "status unhealthy"
              }
            >
              {backendStatus}
            </strong>
          </div>
        </div>
      </section>
    </main>
  );
}

export default App;