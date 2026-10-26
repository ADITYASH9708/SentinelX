                           
import { useEffect, useMemo, useState } from "react";
import "./App.css";

function MLThreatAnalysis() {
  const [analysis, setAnalysis] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function runAnalysis() {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(
        "/api/analyze"
      );

      if (!response.ok) {
        throw new Error("Could not get analysis from backend.");
      }

      const data = await response.json();
      setAnalysis(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="panel" style={{ padding: 20, marginBottom: 24 }}>
      <div className="section-heading">
        <div>
          <h2>ML Threat Analysis</h2>
          <p>Analyze a demonstration login pattern</p>
        </div>
        <span className="notice-tag">ML-001</span>
      </div>

      <p>
        Isolation Forest anomaly detection with an additional
        security rule. This analyzes a sample pattern, not live events.
      </p>

      <button
        className="button-primary"
        onClick={runAnalysis}
        disabled={loading}
      >
        {loading ? "Analyzing..." : "Run ML Analysis"}
      </button>

      {error && (
        <p style={{ color: "#ff7777", marginTop: 12 }}>
          {error}
        </p>
      )}

      {analysis && (
        <div style={{ marginTop: 18 }}>
          <h3>
            Result:{" "}
            <span
              className={
                analysis.status === "SUSPICIOUS" ? "risk" : "result success"
              }
            >
              {analysis.status}
            </span>
          </h3>

          <p>Model: {analysis.model}</p>
          <p>ML prediction: {analysis.ml_prediction}</p>
          <p>
            Security rule triggered:{" "}
            {analysis.rule_triggered ? "Yes" : "No"}
          </p>
          <p>Anomaly score: {analysis.anomaly_score}</p>
          <small>{analysis.note}</small>
        </div>
      )}
    </div>
  );
}

function App() {
  const [logs, setLogs] = useState([]);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("ALL");
  const [page, setPage] = useState("Overview");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;

    async function loadEvents() {
      try {
        const response = await fetch(
          "/api/events"
        );

        if (!response.ok) {
          throw new Error("Backend could not read Windows events.");
        }

        const data = await response.json();

        const realLogs = (data.events || []).map((event) => {
          const match = String(event.time || "").match(/\d+/);
          const date = match
            ? new Date(Number(match[0]))
            : new Date(event.time);

          const message = event.message || "";
          const accountMatch = message.match(
            /Account Name:\s*([^\r\n]+)/i
          );
          const ipMatch = message.match(
            /Source Network Address:\s*([^\r\n]+)/i
          );

          const rawUser = accountMatch?.[1]?.trim();
          const rawIP = ipMatch?.[1]?.trim();

          const user =
            rawUser && rawUser !== "-" && rawUser !== "SYSTEM"
              ? rawUser
              : "Windows account";

          const ip =
            rawIP && rawIP !== "-" && rawIP !== "::1"
              ? rawIP
              : "Local machine";

          return {
            id: event.recordId ?? `${event.id}-${event.time}`,
            time: Number.isNaN(date.getTime())
              ? "--:--:--"
              : date.toLocaleTimeString("en-IN"),
            user,
            ip,
            result: event.result,
          };
        });

        if (active) {
          setLogs(realLogs);
          setError("");
        }
      } catch (err) {
        if (active) setError(err.message);
      } finally {
        if (active) setLoading(false);
      }
    }

    loadEvents();
    const interval = setInterval(loadEvents, 10000);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  const suspiciousUsers = useMemo(() => {
    const counts = {};

    logs.forEach((log) => {
      if (log.result === "FAILED") {
        counts[log.user] = (counts[log.user] || 0) + 1;
      }
    });

    return Object.entries(counts)
      .filter(([, count]) => count >= 3)
      .map(([user]) => user);
  }, [logs]);

  const filteredLogs = logs.filter((log) => {
    const matchesSearch =
      `${log.user} ${log.ip} ${log.result}`
        .toLowerCase()
        .includes(search.toLowerCase());

    const matchesFilter =
      filter === "ALL" || log.result === filter;

    return matchesSearch && matchesFilter;
  });

  function exportCSV() {
    const content = [
      "time,user,ip,result",
      ...filteredLogs.map(
        (log) =>
          `${log.time},${log.user},${log.ip},${log.result}`
      ),
    ].join("\n");

    const link = document.createElement("a");
    const url = URL.createObjectURL(
      new Blob([content], { type: "text/csv" })
    );

    link.href = url;
    link.download = "sentinelx-report.csv";
    link.click();
    URL.revokeObjectURL(url);
  }

  const failed = logs.filter(
    (log) => log.result === "FAILED"
  ).length;

  const flagged = logs.filter(
    (log) => suspiciousUsers.includes(log.user)
  ).length;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">S</div>
          <div>
            <strong>sentinel<span>X</span></strong>
            <small>SECURITY INTELLIGENCE</small>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>

        {["Overview", "Log Explorer", "Threat Alerts"].map(
          (item, i) => (
            <button
              key={item}
              className={`nav-item ${page === item ? "active" : ""}`}
              onClick={() => setPage(item)}
            >
              <span>{["◫", "⌕", "⚠"][i]}</span>
              {item}
              {item === "Threat Alerts" && (
                <b>{suspiciousUsers.length}</b>
              )}
            </button>
          )
        )}

        <div className="sidebar-bottom">
          <div className="status-dot" />
          LOCAL ANALYSIS MODE
          <p>SentinelX v1.0.0</p>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div>
            <span className="breadcrumb">Workspace /</span> {page}
          </div>
          <div className="top-right">
            <span className="online-dot" />
            WINDOWS SECURITY LOGS
            <div className="avatar">SX</div>
          </div>
        </header>

        <section className="content">
          <div className="welcome">
            <div>
              <div className="eyebrow">
                SECURITY OPERATIONS CENTER
              </div>
              <h1>
                {page === "Overview" ? "Command Center" : page}
              </h1>
              <p>
                Monitor authentication events. Investigate
                suspicious patterns.
              </p>
            </div>
          </div>

          <div className="notice">
            <span>✦</span>
            <div>
              <strong>Detection engine active</strong>
              <small>
                Repeated failed logins are flagged when an account
                has 3 or more failed events in the loaded dataset.
              </small>
            </div>
            <span className="notice-tag">RULE-001</span>
          </div>

          {error && (
            <div className="panel" style={{ padding: 16 }}>
              <strong>Connection error</strong>
              <p>{error}</p>
              <small>
                Ensure the Python backend is running on port 5000.
              </small>
            </div>
          )}

          {page !== "Threat Alerts" && (
            <div className="stats-grid">
              <Stat
                label="TOTAL EVENTS"
                value={logs.length}
                detail="Windows authentication records"
                icon="▤"
              />
              <Stat
                label="FAILED LOGINS"
                value={failed}
                detail="Unsuccessful attempts"
                icon="↗"
              />
              <Stat
                label="FLAGGED EVENTS"
                value={flagged}
                detail="Events linked to flagged accounts"
                icon="⚑"
              />
              <Stat
                label="USERS FLAGGED"
                value={suspiciousUsers.length}
                detail="Require further investigation"
                icon="◎"
              />
            </div>
          )}

          {page === "Overview" && (
            <>
              <MLThreatAnalysis />

              <div className="section-heading">
                <div>
                  <h2>Authentication activity</h2>
                  <p>Currently loaded Windows events</p>
                </div>
                <span className="live-pill">
                  ● {loading ? "LOADING" : "DATA LOADED"}
                </span>
              </div>

              <div className="panel chart-panel">
                <div className="chart-legend">
                  <span>
                    <i className="legend-success" /> Successful
                  </span>
                  <span>
                    <i className="legend-failed" /> Failed
                  </span>
                </div>

                <div className="bar-chart">
                  {Array.from({ length: 8 }, (_, i) => {
                    const group = logs.slice(i * 6, i * 6 + 6);
                    const successCount = group.filter(
                      (log) => log.result === "SUCCESS"
                    ).length;
                    const failedCount = group.filter(
                      (log) => log.result === "FAILED"
                    ).length;

                    return (
                      <div className="bar-group" key={i}>
                        <div className="bars">
                          <div
                            className="bar success-bar"
                            style={{
                              height: `${Math.max(4, successCount * 18)}%`,
                            }}
                          />
                          <div
                            className="bar failed-bar"
                            style={{
                              height: `${Math.max(4, failedCount * 18)}%`,
                            }}
                          />
                        </div>
                        <small>{i + 1}</small>
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          )}

          {(page === "Overview" || page === "Log Explorer") && (
            <>
              <div className="section-heading">
                <div>
                  <h2>
                    {page === "Overview"
                      ? "Recent authentication events"
                      : "Log Explorer"}
                  </h2>
                  <p>Search and filter Windows login records</p>
                </div>
                <button
                  className="button-secondary"
                  onClick={exportCSV}
                >
                  ↓ Export CSV
                </button>
              </div>

              <div className="panel table-panel">
                <div className="table-tools">
                  <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search user, IP or result..."
                  />
                  <select
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                  >
                    <option value="ALL">All results</option>
                    <option value="SUCCESS">Success</option>
                    <option value="FAILED">Failed</option>
                  </select>
                </div>

                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>TIME</th>
                        <th>USER</th>
                        <th>SOURCE IP</th>
                        <th>RESULT</th>
                        <th>DETECTION</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredLogs.map((log) => (
                        <tr key={log.id}>
                          <td className="mono">{log.time}</td>
                          <td className="user-cell">{log.user}</td>
                          <td className="mono">{log.ip}</td>
                          <td>
                            <span
                              className={`result ${log.result.toLowerCase()}`}
                            >
                              {log.result}
                            </span>
                          </td>
                          <td>
                            {suspiciousUsers.includes(log.user) ? (
                              <span className="risk">⚑ Review</span>
                            ) : (
                              <span className="muted">—</span>
                            )}
                          </td>
                        </tr>
                      ))}
                      {!filteredLogs.length && (
                        <tr>
                          <td colSpan="5" className="empty">
                            {loading
                              ? "Loading Windows events..."
                              : "No matching events found."}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                <div className="table-footer">
                  Showing {filteredLogs.length} of {logs.length} events
                  <span>
                    Rule-based detection · Windows event logs
                  </span>
                </div>
              </div>
            </>
          )}

          {page === "Threat Alerts" && (
            <div className="alerts-list">
              {suspiciousUsers.length ? (
                suspiciousUsers.map((user) => (
                  <div className="panel alert-card" key={user}>
                    <div className="alert-symbol">!</div>
                    <div className="alert-copy">
                      <span className="risk">NEEDS REVIEW</span>
                      <h3>Repeated failed login attempts</h3>
                      <p>
                        Account <strong>{user}</strong> has{" "}
                        {
                          logs.filter(
                            (log) =>
                              log.user === user &&
                              log.result === "FAILED"
                          ).length
                        }{" "}
                        failed attempts in the loaded dataset.
                      </p>
                      <small>
                        This is a heuristic alert, not proof of an attack.
                      </small>
                    </div>
                  </div>
                ))
              ) : (
                <div className="panel empty-alert">
                  {loading
                    ? "Loading Windows events..."
                    : "No accounts currently meet the failed-login threshold."}
                </div>
              )}
            </div>
          )}

          <footer>
            SENTINELX <span>·</span> DEFENSIVE SECURITY ANALYTICS{" "}
            <span>·</span> WINDOWS EVENT DATA
          </footer>
        </section>
      </main>
    </div>
  );
}

function Stat({ label, value, detail, icon }) {
  return (
    <div className="panel stat-card">
      <div className="stat-top">
        <span>{label}</span>
        <span className="stat-icon">{icon}</span>
      </div>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

export default App;
