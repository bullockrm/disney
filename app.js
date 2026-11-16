// Client-side decryption. The plan is stored encrypted in data/plan.enc.json.
// Nothing is decrypted until the passcode is entered, and nothing is saved in the browser.

const ENC_URL = "data/plan.enc.json";
let plan = null;

const state = {
  group: "ALL",
  day: "ALL",
  type: "ALL",
  query: "",
  llGroup: "ALL",
  diningStatus: "ALL",
  diningGroup: "ALL",
};

const TYPES = ["dining", "lightning", "show", "attraction", "travel"];

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Derives the AES key from the passcode. The key is extractable so it can be
// remembered on this device (as raw bytes), not the passcode itself.
async function deriveKey(passcode, enc) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passcode),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64ToBytes(enc.salt), iterations: enc.iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["decrypt"]
  );
}

async function decryptWithKey(key, enc) {
  // WebCrypto expects ciphertext and tag concatenated.
  const data = b64ToBytes(enc.data);
  const tag = b64ToBytes(enc.tag);
  const combined = new Uint8Array(data.length + tag.length);
  combined.set(data);
  combined.set(tag, data.length);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(enc.iv) }, key, combined);
  return JSON.parse(new TextDecoder().decode(plain));
}

// Remembered unlock: the raw AES key plus the salt it was derived with.
// If the plan is re-encrypted (new salt), the remembered key is ignored.
const REMEMBER_KEY = "disney-plan-unlock";

function readRemembered(enc) {
  try {
    const saved = JSON.parse(localStorage.getItem(REMEMBER_KEY) || "null");
    if (!saved || saved.salt !== enc.salt) return null;
    return saved;
  } catch {
    return null;
  }
}

async function importRemembered(saved) {
  return crypto.subtle.importKey(
    "raw",
    b64ToBytes(saved.key),
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
}

async function rememberKey(key, enc) {
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  let bin = "";
  raw.forEach((b) => (bin += String.fromCharCode(b)));
  localStorage.setItem(REMEMBER_KEY, JSON.stringify({ salt: enc.salt, key: btoa(bin) }));
}

function forgetDevice() {
  localStorage.removeItem(REMEMBER_KEY);
  location.reload();
}

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c == null) continue;
    node.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

function chip(label, active, onClick) {
  const b = el("button", { class: "chip" + (active ? " on" : ""), type: "button" }, label);
  b.addEventListener("click", onClick);
  return b;
}

function groupLabel(id) {
  if (id === "ALL") return "All";
  const g = plan.groups.find((x) => x.id === id);
  return g ? g.id : id;
}

function groupsText(groups) {
  if (groups.length === plan.groups.length) return "All groups";
  return groups.join(", ");
}

function matchesGroup(groups, selected) {
  return selected === "ALL" || groups.includes("ALL") || groups.includes(selected);
}

function eventCard(ev, dayLabel) {
  const classes = ["event", ev.type];
  if (ev.status === "open") classes.push("open");
  if (ev.status === "proposed") classes.push("proposed");
  const badges = [];
  if (ev.status === "open") badges.push(el("span", { class: "badge open" }, "Open"));
  if (ev.status === "proposed") badges.push(el("span", { class: "badge proposed" }, "Proposed"));
  return el("div", { class: classes.join(" ") }, [
    el("div", { class: "time" }, ev.time),
    el("div", { class: "title" }, [...badges, ev.title]),
    el("div", { class: "meta" }, [
      ev.location ? ev.location + " · " : "",
      groupsText(ev.groups),
      dayLabel ? " · " + dayLabel : "",
    ]),
    ev.notes ? el("div", { class: "notes" }, ev.notes) : null,
  ]);
}

function renderItinerary() {
  const groupChips = document.getElementById("group-chips");
  const dayChips = document.getElementById("day-chips");
  const typeChips = document.getElementById("type-chips");
  const days = document.getElementById("days");
  groupChips.replaceChildren();
  dayChips.replaceChildren();
  typeChips.replaceChildren();
  days.replaceChildren();

  const groupOpts = ["ALL", ...plan.groups.map((g) => g.id)];
  for (const g of groupOpts) {
    groupChips.append(chip(g === "ALL" ? "All groups" : g, state.group === g, () => {
      state.group = g; renderItinerary();
    }));
  }
  dayChips.append(chip("All days", state.day === "ALL", () => { state.day = "ALL"; renderItinerary(); }));
  for (const d of plan.days) {
    dayChips.append(chip(d.label, state.day === d.id, () => { state.day = d.id; renderItinerary(); }));
  }
  typeChips.append(chip("All types", state.type === "ALL", () => { state.type = "ALL"; renderItinerary(); }));
  for (const t of TYPES) {
    typeChips.append(chip(t[0].toUpperCase() + t.slice(1), state.type === t, () => {
      state.type = t; renderItinerary();
    }));
  }

  const q = state.query.trim().toLowerCase();
  let shown = 0;
  for (const d of plan.days) {
    if (state.day !== "ALL" && state.day !== d.id) continue;
    const matches = d.events.filter((ev) => {
      if (!matchesGroup(ev.groups, state.group)) return false;
      if (state.type !== "ALL" && ev.type !== state.type) return false;
      if (q) {
        const hay = [ev.title, ev.location, ev.notes, ev.time].join(" ").toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    if (!matches.length) continue;
    shown += matches.length;
    days.append(el("div", { class: "day" }, [
      el("h3", {}, d.label),
      ...matches.map((ev) => eventCard(ev)),
    ]));
  }
  if (!shown) days.append(el("p", { class: "meta" }, "Nothing matches these filters."));
}

function renderLightning() {
  const chips = document.getElementById("ll-group-chips");
  const list = document.getElementById("ll-list");
  chips.replaceChildren();
  list.replaceChildren();

  for (const g of ["ALL", ...plan.groups.map((x) => x.id)]) {
    chips.append(chip(g === "ALL" ? "All groups" : g, state.llGroup === g, () => {
      state.llGroup = g; renderLightning();
    }));
  }
  for (const item of plan.lightning) {
    const involves = item.group === "ALL" || state.llGroup === "ALL" || item.group.split(/ and |, /).includes(state.llGroup);
    if (!involves) continue;
    list.append(el("div", { class: "card" }, [
      el("div", { class: "label" }, item.park),
      el("div", {}, item.group),
      el("div", { class: "meta" }, item.items),
    ]));
  }

  const tips = document.getElementById("pass-tips");
  tips.replaceChildren(...plan.passes.map((p) => el("li", {}, p)));
}

function renderDining() {
  const groupChips = document.getElementById("dining-group-chips");
  const chips = document.getElementById("dining-status-chips");
  const list = document.getElementById("dining-list");
  groupChips.replaceChildren();
  chips.replaceChildren();
  list.replaceChildren();

  for (const g of ["ALL", ...plan.groups.map((x) => x.id)]) {
    groupChips.append(chip(g === "ALL" ? "All groups" : g, state.diningGroup === g, () => {
      state.diningGroup = g; renderDining();
    }));
  }
  for (const s of ["ALL", "booked", "open"]) {
    const label = s === "ALL" ? "All" : s === "booked" ? "Booked" : "Open";
    chips.append(chip(label, state.diningStatus === s, () => {
      state.diningStatus = s; renderDining();
    }));
  }

  let shown = 0;
  for (const d of plan.dining) {
    if (state.diningStatus !== "ALL" && d.status !== state.diningStatus) continue;
    if (!matchesGroup(d.who.split(/,\s*/), state.diningGroup)) continue;
    shown++;
    list.append(el("div", { class: "card" }, [
      el("div", { class: "label" }, d.place),
      el("div", { class: "meta" }, `${d.date} · ${d.time} · ${d.who === "ALL" ? "All groups" : d.who}`),
      el("span", { class: "badge " + d.status }, d.status === "open" ? "Open" : "Booked"),
      d.note ? el("div", { class: "notes" }, d.note) : null,
    ]));
  }
  if (!shown) list.append(el("p", { class: "meta" }, "No dining plans match these filters."));
}

function renderTravel() {
  const flights = document.getElementById("flights");
  const rooms = document.getElementById("rooms");
  flights.replaceChildren(...plan.flights.map((f) => el("div", { class: "card" }, [
    el("div", { class: "label" }, `${f.direction}: ${f.flight}`),
    el("div", {}, f.route),
    el("div", { class: "meta" }, `Depart ${f.depart} · Arrive ${f.arrive}`),
    el("div", { class: "meta" }, f.seats),
  ])));

  rooms.replaceChildren(
    el("div", { class: "card" }, [
      el("div", { class: "label" }, "Room types"),
      ...plan.rooms.types.map((t) => el("div", { class: "meta" }, `${t.group}: ${t.room}`)),
    ]),
    el("div", { class: "card" }, [
      el("div", { class: "label" }, "Requests"),
      el("div", { class: "meta" }, plan.rooms.note),
      el("ul", {}, plan.rooms.requests.map((r) => el("li", {}, r))),
    ]),
  );
}

function renderOpen() {
  const list = document.getElementById("open-list");
  list.replaceChildren(...plan.open_items.map((i) => el("li", {}, i)));
}

function renderAll() {
  renderItinerary();
  renderLightning();
  renderDining();
  renderTravel();
  renderOpen();
}

function wireTabs() {
  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b === btn));
      document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === btn.dataset.tab));
    });
  });
  document.getElementById("search").addEventListener("input", (e) => {
    state.query = e.target.value;
    renderItinerary();
  });
}

function showPlan(decrypted) {
  plan = decrypted;
  document.getElementById("lock").hidden = true;
  document.getElementById("app").hidden = false;
  document.getElementById("forget").hidden = false;
  renderAll();
}

async function loadEnc() {
  const res = await fetch(ENC_URL, { cache: "no-store" });
  if (!res.ok) throw new Error("Could not load the plan.");
  return res.json();
}

async function tryRemembered() {
  try {
    const enc = await loadEnc();
    const saved = readRemembered(enc);
    if (!saved) return;
    const key = await importRemembered(saved);
    showPlan(await decryptWithKey(key, enc));
  } catch {
    // Remembered key is stale or unreadable: fall back to the passcode screen.
    localStorage.removeItem(REMEMBER_KEY);
  }
}

async function unlock(event) {
  event.preventDefault();
  const input = document.getElementById("passcode");
  const error = document.getElementById("lock-error");
  const remember = document.getElementById("remember").checked;
  error.hidden = true;
  try {
    const enc = await loadEnc();
    const key = await deriveKey(input.value, enc);
    const decrypted = await decryptWithKey(key, enc);
    if (remember) await rememberKey(key, enc);
    input.value = "";
    renderDots();
    showPlan(decrypted);
  } catch (err) {
    error.hidden = false;
    input.value = "";
    renderDots();
  }
}

const MAX_DIGITS = 12;

function renderDots() {
  const input = document.getElementById("passcode");
  const dots = document.getElementById("dots");
  dots.replaceChildren(...Array.from({ length: input.value.length }, () => el("span", { class: "filled" })));
}

function wireKeypad() {
  const input = document.getElementById("passcode");
  document.querySelectorAll("#keypad .key[data-key]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (input.value.length >= MAX_DIGITS) return;
      input.value += btn.dataset.key;
      document.getElementById("lock-error").hidden = true;
      renderDots();
    });
  });
  document.getElementById("key-back").addEventListener("click", () => {
    input.value = input.value.slice(0, -1);
    renderDots();
  });
  document.getElementById("key-clear").addEventListener("click", () => {
    input.value = "";
    renderDots();
  });
}

document.getElementById("unlock-form").addEventListener("submit", unlock);
document.getElementById("forget").addEventListener("click", forgetDevice);
wireKeypad();
renderDots();
wireTabs();
tryRemembered();
