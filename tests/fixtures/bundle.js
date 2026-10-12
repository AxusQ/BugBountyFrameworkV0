/* Fixture bundle for end-to-end pipeline validation.
 * Realistic shape, synthetic content. Contains one third-party host on purpose,
 * so the asset boundary has something to block. */

const API_BASE = "/api/v1";

async function loadReports() {
  const res = await fetch(`${API_BASE}/reports?sort=created_at&order=desc&filter=status&limit=50`);
  return res.json();
}

const requestParams = {
  params: {
    column: "created_at",
    direction: "asc",
    group: "status",
    fields: "id,title,owner",
    username: "current_user",
    page: 1,
    per_page: 25
  }
};

axios.get("/internal/admin/users", requestParams);
axios.post("/api/v2/export/report", { format: "csv" });

// Escape hatches: places where parameterisation guarantees stop applying.
const rows = await db.whereRaw("status = 1");
const built = knex.raw("select * from audit_log where actor = ?", [actorId]);
const composed = `SELECT id, title FROM reports WHERE owner_id = ${ownerId} ORDER BY ${sortColumn}`;

fetch("https://analytics.thirdparty-vendor.com/collect", { method: "POST" });
fetch("https://cdn.unrelated-customer.net/beacon.gif");

//# sourceMappingURL=/static/js/app.bundle.js.map
