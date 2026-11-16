// Client-side decryption. The plan is stored encrypted in data/plan.enc.json.
// Nothing is decrypted until the passcode is entered, and only the derived key is remembered.

const ENC_URL = "data/plan.enc.json";
const REMEMBER_KEY = "disney-plan-unlock";
const THEME_KEY = "disney-theme";
const THEMES = ["sunset", "castle", "teal"];
const TYPES = ["dining", "lightning", "show", "attraction", "travel"];
const MAX_DIGITS = 12;

// Dining entries have no park field, so map the place name to its park.
const DINING_PARK = {
  "Tusker House": "Animal Kingdom",
  "Garden Grill": "EPCOT",
  "Biergarten": "EPCOT",
  "Cinderella's Royal Table": "Magic Kingdom",
  "Hollywood & Vine": "Hollywood Studios",
  "Roundup Rodeo BBQ": "Magic Kingdom",
};

let plan = null;

const state = {
  group: "ALL",
  day: "ALL",
  type: "ALL",
  query: "",
  llGroup: "ALL",
  diningGroup: "ALL",
};

// ---------- Crypto ----------

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
  return crypto.subtle.importKey("raw", b64ToBytes(saved.key), { name: "AES-GCM" }, false, ["decrypt"]);
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

// ---------- Helpers ----------

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

function matchesGroup(groups, selected) {
  return selected === "ALL" || groups.includes("ALL") || groups.includes(selected);
}

// Group chips with the same colors in every theme. Accepts ids such as ["LP", "RB"].
function groupChips(ids) {
  const all = ids.includes("ALL") || ids.length === plan.groups.length;
  if (all) return [el("span", { class: "g ALL" }, "All")];
  return ids.map((id) => el("span", { class: "g " + id }, id));
}

// Turns the lightning summary labels ("LP and RB", "ALL") into group ids.
function idsFromLabel(label) {
  return label === "ALL" ? ["ALL"] : label.split(/ and |, /);
}

// Park class from a location string, using the park that appears first in it.
function parkClass(location) {
  const parks = [
    ["Magic Kingdom", "p-MK"],
    ["EPCOT", "p-EP"],
    ["Hollywood Studios", "p-HS"],
    ["Animal Kingdom", "p-AK"],
  ];
  let best = null;
  for (const [name, cls] of parks) {
    const i = location ? location.indexOf(name) : -1;
    if (i !== -1 && (best === null || i < best.i)) best = { i, cls };
  }
  return best ? best.cls : "p-none";
}

// ---------- Itinerary ----------

function eventCard(ev, dayLabel) {
  const classes = ["event", ev.type, parkClass(ev.location)];
  if (ev.status === "proposed") classes.push("proposed");
  const badges = [];
  if (ev.status === "open") badges.push(el("span", { class: "badge open" }, "Open"));
  if (ev.status === "proposed") badges.push(el("span", { class: "badge proposed" }, "Proposed"));
  return el("div", { class: classes.join(" ") }, [
    el("div", { class: "time" }, ev.time),
    el("div", { class: "title" }, [...badges, ev.title]),
    el("div", { class: "meta" }, [ev.location || "", dayLabel ? " · " + dayLabel : ""]),
    el("div", { class: "grp" }, groupChips(ev.groups)),
    ev.notes ? el("div", { class: "notes" }, ev.notes) : null,
  ]);
}

function renderItinerary() {
  const groupChipsEl = document.getElementById("group-chips");
  const dayChips = document.getElementById("day-chips");
  const typeChips = document.getElementById("type-chips");
  const days = document.getElementById("days");
  groupChipsEl.replaceChildren();
  dayChips.replaceChildren();
  typeChips.replaceChildren();
  days.replaceChildren();

  for (const g of ["ALL", ...plan.groups.map((x) => x.id)]) {
    groupChipsEl.append(chip(g === "ALL" ? "All groups" : g, state.group === g, () => {
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
    // Headers and cards are direct children of one list, so each sticky header
    // stays pinned until the next day's header slides up over it.
    days.append(dayHeader(d.label), ...matches.map((ev) => eventCard(ev)));
  }
  if (!shown) days.append(el("p", { class: "meta" }, "Nothing matches these filters."));
}

// Sticky date header shared by the itinerary, Lightning Lanes and dining lists.
function dayHeader(label) {
  return el("h3", { class: "day-h" }, label);
}

// ---------- Lightning Lanes ----------

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
  // Lightning Lanes come from the day events, so each one sits under its date.
  let shown = 0;
  for (const d of plan.days) {
    const lanes = d.events.filter((ev) =>
      ev.type === "lightning" && matchesGroup(ev.groups, state.llGroup));
    if (!lanes.length) continue;
    shown += lanes.length;
    list.append(dayHeader(d.label), ...lanes.map((ev) => eventCard(ev)));
  }
  if (!shown) list.append(el("p", { class: "meta" }, "No Lightning Lanes match this group."));

  const tips = document.getElementById("pass-tips");
  tips.replaceChildren(...plan.passes.map((p) => el("li", {}, p)));
}

// ---------- Dining ----------

function renderDining() {
  const groupChipsEl = document.getElementById("dining-group-chips");
  const list = document.getElementById("dining-list");
  groupChipsEl.replaceChildren();
  list.replaceChildren();

  for (const g of ["ALL", ...plan.groups.map((x) => x.id)]) {
    groupChipsEl.append(chip(g === "ALL" ? "All groups" : g, state.diningGroup === g, () => {
      state.diningGroup = g; renderDining();
    }));
  }

  // Dining is grouped under each day's date header, in itinerary order.
  let shown = 0;
  for (const day of plan.days) {
    const meals = plan.dining.filter((d) => {
      if (d.date !== day.label) return false;
      return matchesGroup(idsFromLabel(d.who), state.diningGroup);
    });
    if (!meals.length) continue;
    shown += meals.length;
    list.append(dayHeader(day.label));
    for (const d of meals) {
      const ids = idsFromLabel(d.who);
      list.append(el("div", { class: "card " + parkClass(DINING_PARK[d.place]) }, [
        el("div", { class: "label" }, d.place),
        el("div", { class: "meta" }, d.time),
        el("div", { class: "grp" }, groupChips(ids)),
        d.note ? el("div", { class: "notes" }, d.note) : null,
      ]));
    }
  }
  if (!shown) list.append(el("p", { class: "meta" }, "No dining plans match these filters."));
}

// ---------- Travel & rooms ----------

function renderTravel() {
  const flights = document.getElementById("flights");
  const rooms = document.getElementById("rooms");
  flights.replaceChildren(...plan.flights.map((f) => el("div", { class: "card p-none" }, [
    el("div", { class: "label" }, `${f.direction}: ${f.flight}`),
    el("div", {}, f.route),
    el("div", { class: "meta" }, `Depart ${f.depart} · Arrive ${f.arrive}`),
    el("div", { class: "meta" }, f.seats),
  ])));

  rooms.replaceChildren(
    el("div", { class: "card p-none" }, [
      el("div", { class: "label" }, "Room types"),
      ...plan.rooms.types.map((t) => el("div", { class: "meta" }, `${t.group}: ${t.room}`)),
    ]),
    el("div", { class: "card p-none" }, [
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

// ---------- Theme ----------

function applyTheme(name) {
  const theme = THEMES.includes(name) ? name : "castle";
  document.documentElement.dataset.theme = theme;
  document.querySelectorAll(".swatch").forEach((btn) => {
    btn.setAttribute("aria-pressed", String(btn.dataset.theme === theme));
  });
  try { localStorage.setItem(THEME_KEY, theme); } catch { /* storage unavailable */ }
}

function wireTheme() {
  document.querySelectorAll(".swatch").forEach((btn) => {
    btn.addEventListener("click", () => applyTheme(btn.dataset.theme));
  });
  let saved = null;
  try { saved = localStorage.getItem(THEME_KEY); } catch { /* storage unavailable */ }
  applyTheme(saved);
}

// ---------- Navigation and unlock ----------

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

document.getElementById("unlock-form").addEventListener("submit", unlock);
document.getElementById("forget").addEventListener("click", forgetDevice);
document.getElementById("refresh").addEventListener("click", () => location.reload());
wireKeypad();
renderDots();
wireTabs();
wireTheme();
tryRemembered();
