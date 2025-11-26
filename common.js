const DATA_URL = "data/components.json";

async function loadAllComponents() {
    const res = await fetch(DATA_URL, { cache: "no-store" });
    if (!res.ok) throw new Error("Failed to load SBOM data");
    return await res.json();
}

function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}
