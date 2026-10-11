// Tiny helpers. All data is inserted with textContent, never innerHTML, except sanitized Markdown.
export function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "href") n.setAttribute("href", v);
    else n[k] = v;
  }
  for (const k of kids.flat()) if (k != null) n.append(k.nodeType ? k : document.createTextNode(String(k)));
  return n;
}
export async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}
export async function post(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: body ? { "content-type": "application/json" } : {},
    body: body ? JSON.stringify(body) : null,
  });
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}
export function pill(text, cls = "") { return el("span", { class: `pill ${cls}` }, text); }
export function sourceBadge(source, note) {
  return el("span", { class: "muted", title: note || "" }, source === "live" ? "● live" : "○ placeholder");
}
export function table(cols, rows, empty) {
  if (!rows.length) return el("p", { class: "muted" }, empty);
  return el("table", {},
    el("thead", {}, el("tr", {}, cols.map(c => el("th", {}, c.label)))),
    el("tbody", {}, rows.map(r => el("tr", {}, cols.map(c => el("td", {}, c.render(r)))))));
}
export function renderMarkdown(target, md) {
  if (window.marked && window.DOMPurify) target.innerHTML = DOMPurify.sanitize(marked.parse(md));
  else target.replaceChildren(el("pre", {}, md));
}
