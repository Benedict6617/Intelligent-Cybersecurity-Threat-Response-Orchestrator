// Minimal analyst dashboard for the Intelligent Cybersecurity Threat
// Response Orchestrator. No build step / framework - plain fetch calls
// against the FastAPI backend, refreshed on load and via the Refresh
// button. Intended as a reference UI; swap in your organization's SSO
// and a proper frontend framework for production deployment at scale.

const API_BASE = window.location.origin + "/api/v1";
document.getElementById("api-base-label").textContent = API_BASE;

async function getJSON(path) {
  const resp = await fetch(API_BASE + path);
  if (!resp.ok) throw new Error(`${path} -> ${resp.status}`);
  return resp.json();
}

function sevBadge(sev) {
  return `<span class="sev-badge sev-${sev}">${sev}</span>`;
}

function fmtTime(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

async function loadSummary() {
  const summary = await getJSON("/dashboard/summary");
  document.getElementById("m-open").textContent = summary.open_incidents;
  document.getElementById("m-critical").textContent = summary.critical_open;
  document.getElementById("m-events").textContent = summary.events_last_24h;
  document.getElementById("m-fp").textContent = summary.false_positives_suppressed_last_24h;

  const list = document.getElementById("technique-list");
  if (!summary.top_mitre_techniques || summary.top_mitre_techniques.length === 0) {
    list.innerHTML = '<span class="empty-state">No technique matches yet — ingest events to populate.</span>';
  } else {
    list.innerHTML = summary.top_mitre_techniques
      .map(t => `<span class="technique-chip">${t.technique_id}<span class="count">×${t.count}</span></span>`)
      .join("");
  }
}

async function loadIncidents() {
  const incidents = await getJSON("/incidents");
  const tbody = document.getElementById("incident-rows");
  if (!incidents.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No incidents yet. Run scripts/simulate_attack.py to load sample data.</td></tr>';
    return;
  }
  tbody.innerHTML = incidents
    .slice(0, 25)
    .map(inc => `
      <tr class="incident-row" title="${inc.id}">
        <td>${sevBadge(inc.severity)}</td>
        <td>${inc.title}</td>
        <td class="mono">${(inc.mitre_techniques || []).join(", ") || "–"}</td>
        <td class="mono">${inc.confidence_score}%</td>
        <td class="mono">${inc.status}</td>
        <td class="mono">${fmtTime(inc.created_at)}</td>
      </tr>
    `)
    .join("");
}

async function refreshAll() {
  const statusLine = document.getElementById("status-line");
  try {
    await Promise.all([loadSummary(), loadIncidents()]);
    statusLine.textContent = `connected · last updated ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    statusLine.textContent = "API unreachable — is uvicorn running?";
    console.error(err);
  }
}

document.getElementById("refresh-btn").addEventListener("click", refreshAll);
refreshAll();
setInterval(refreshAll, 30000);
