// Client-side decryption. The plan is stored encrypted in data/plan.enc.json.
// Nothing is decrypted until the passcode is entered, and only the derived key is remembered.

const ENC_URL = "data/plan.enc.json";
const REMEMBER_KEY = "disney-plan-unlock";
const THEME_KEY = "disney-theme";
const GROUP_KEY = "disney-group";
const DONE_KEY = "disney-done";
const NOTES_KEY = "disney-notes";
const FAV_KEY = "disney-favorites";
const THEMES = ["sunset", "castle", "teal"];
const TYPES = ["dining", "lightning", "show", "attraction", "travel"];
const MAX_DIGITS = 12;
const PARKS = [
  ["Magic Kingdom", "MK"],
  ["EPCOT", "EP"],
  ["Hollywood Studios", "HS"],
  ["Animal Kingdom", "AK"],
];
// Planning assumptions for the timing checks, in minutes.
const SAME_PARK_WALK = 10;
const PARK_TRANSFER = 60;
const FIXED_GRACE = 10;
// Orlando is on Eastern Standard Time (UTC-5) for the whole trip.
const ET_OFFSET_HOURS = 5;
// Live standby waits for all of Walt Disney World, from ThemeParks.wiki.
const WAITS_URL = "https://api.themeparks.wiki/v1/entity/e957da41-3552-4cf6-b636-5babc5cbc4e5/live";

let plan = null;
let waits = null; // Map of normalized ride name -> { wait, status }
let waitsState = "idle";

const state = {
  group: readStore(GROUP_KEY, "ALL"),
  day: "ALL",
  type: "ALL",
  query: "",
  timelineDay: null,
};

function readStore(key, fallback) {
  try {
    const v = JSON.parse(localStorage.getItem(key));
    return v == null ? fallback : v;
  } catch {
    return fallback;
  }
}
function writeStore(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable */ }
}

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
    if (v == null || v === false) continue;
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

// Turns the dining labels ("LP, RB", "ALL") into group ids.
function idsFromLabel(label) {
  return label === "ALL" ? ["ALL"] : label.split(/ and |, /);
}

// The park named first in a location string, as its short code (MK, EP, HS, AK).
function parkCode(location) {
  let best = null;
  for (const [name, code] of PARKS) {
    const i = location ? location.indexOf(name) : -1;
    if (i !== -1 && (best === null || i < best.i)) best = { i, code };
  }
  return best ? best.code : null;
}
function parkClass(location) {
  const code = parkCode(location);
  return code ? "p-" + code : "p-none";
}

// One group filter shared by every tab and remembered on this device.
function groupFilter(container, rerender) {
  container.replaceChildren();
  for (const g of ["ALL", ...plan.groups.map((x) => x.id)]) {
    container.append(chip(g === "ALL" ? "All groups" : g, state.group === g, () => {
      state.group = g;
      writeStore(GROUP_KEY, g);
      renderAll();
    }));
  }
}

function minutes(hhmm) {
  if (!hhmm) return null;
  const [h, m] = hhmm.split(":").map(Number);
  return h * 60 + m;
}
function clock(mins) {
  const h = Math.floor(mins / 60) % 24;
  const m = mins % 60;
  return `${h % 12 || 12}:${String(m).padStart(2, "0")} ${h < 12 ? "AM" : "PM"}`;
}
function span(mins) {
  if (mins < 60) return `${mins} min`;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return m ? `${h} hr ${m} min` : `${h} hr`;
}

// Current date and time in Orlando. "?now=2026-11-22T14:10" previews another moment.
function nowET() {
  const preview = new URLSearchParams(location.search).get("now");
  const m = preview && preview.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2})/);
  if (m) return { date: m[1], mins: +m[2] * 60 + +m[3] };
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/New_York", hourCycle: "h23",
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
  }).formatToParts(new Date()).map((p) => [p.type, p.value]));
  return { date: `${parts.year}-${parts.month}-${parts.day}`, mins: +parts.hour * 60 + +parts.minute };
}

function daysBetween(a, b) {
  return Math.round((Date.parse(b + "T00:00:00Z") - Date.parse(a + "T00:00:00Z")) / 86400000);
}

// ---------- Timing checks ----------

// Walks one group's day in order and reports stops that cannot be reached in time.
// A Lightning Lane can be used any time in its window; meals and shows have a fixed start.
function walkDay(day, groupId) {
  const stops = day.events.filter((ev) =>
    ev.start && ev.type !== "travel" && ev.status !== "proposed" && ev.groups.includes(groupId));
  const reached = [];
  const warnings = [];
  let free = null;
  let prev = null;
  for (const ev of stops) {
    const start = minutes(ev.start);
    const latest = ev.end ? minutes(ev.end) : start + FIXED_GRACE;
    let arrive = start;
    if (prev) {
      const samePlace = (parkCode(prev.location) || prev.location) === (parkCode(ev.location) || ev.location);
      arrive = Math.max(start, free + (samePlace ? SAME_PARK_WALK : PARK_TRANSFER));
    }
    if (arrive > latest) {
      warnings.push({ ev, prev, group: groupId, arrive, latest });
      continue;
    }
    reached.push({ ev, arrive, leave: arrive + (ev.dur || 0) });
    free = arrive + (ev.dur || 0);
    prev = ev;
  }
  return { reached, warnings };
}

function warningText(w) {
  const where = (ev) => ev.location;
  return `${w.group}: ${w.ev.title} (${w.ev.time}, ${where(w.ev)}) is not reachable after ` +
    `${w.prev.title} (${where(w.prev)}). Earliest arrival is about ${clock(w.arrive)}.`;
}

function dayWarnings(day) {
  const out = [];
  for (const g of plan.groups) {
    if (state.group !== "ALL" && state.group !== g.id) continue;
    out.push(...walkDay(day, g.id).warnings);
  }
  return out;
}

function warningList(warnings) {
  if (!warnings.length) return null;
  return el("div", { class: "warn-box" }, [
    el("div", { class: "warn-title" }, "Timing warnings"),
    el("ul", {}, warnings.map((w) => el("li", {}, warningText(w)))),
  ]);
}

// ---------- Done marks, notes, directions ----------

function isDone(id) { return !!readStore(DONE_KEY, {})[id]; }
function toggleDone(id) {
  const done = readStore(DONE_KEY, {});
  if (done[id]) delete done[id]; else done[id] = true;
  writeStore(DONE_KEY, done);
}
function noteFor(id) { return readStore(NOTES_KEY, {})[id] || ""; }
function saveNote(id, text) {
  const notes = readStore(NOTES_KEY, {});
  if (text.trim()) notes[id] = text.trim(); else delete notes[id];
  writeStore(NOTES_KEY, notes);
}

function mapsUrl(name, location) {
  const clean = name.replace(/\s*\(.*?\)/g, "").replace(/^(Lunch|Dinner) at /, "").replace(/ LL$/, "");
  return "https://www.google.com/maps/search/?api=1&query=" +
    encodeURIComponent(`${clean}, ${location}, Walt Disney World`);
}

// Done checkbox, personal note and directions link. Marks and notes stay on this device.
function isFav(id) { return !!readStore(FAV_KEY, {})[id]; }
function toggleFav(id) {
  const favs = readStore(FAV_KEY, {});
  if (favs[id]) delete favs[id]; else favs[id] = true;
  writeStore(FAV_KEY, favs);
}

function cardActions(id, name, location, canFavorite) {
  const noteBox = el("textarea", { class: "note-input", rows: "2", placeholder: "Note (saved on this device)", hidden: "" });
  noteBox.value = noteFor(id);
  if (noteBox.value) noteBox.hidden = false;
  noteBox.addEventListener("change", () => saveNote(id, noteBox.value));

  const done = el("button", { type: "button", class: "act" + (isDone(id) ? " on" : ""), "aria-pressed": String(isDone(id)) },
    isDone(id) ? "✓ Done" : "Done");
  done.addEventListener("click", () => { toggleDone(id); renderAll(); });

  const note = el("button", { type: "button", class: "act" }, "Note");
  note.addEventListener("click", () => {
    noteBox.hidden = !noteBox.hidden && !noteBox.value;
    if (!noteBox.hidden) noteBox.focus();
  });

  const row = [done, note];
  if (canFavorite) {
    const fav = el("button", { type: "button", class: "act fav" + (isFav(id) ? " on" : ""), "aria-pressed": String(isFav(id)) },
      isFav(id) ? "★ Favorite" : "☆ Favorite");
    fav.addEventListener("click", () => { toggleFav(id); renderWish(); });
    row.unshift(fav);
  }
  if (location) {
    row.push(el("a", { class: "act", href: mapsUrl(name, location), target: "_blank", rel: "noopener" }, "Directions"));
  }
  return [el("div", { class: "actions" }, row), noteBox];
}

// ---------- Live waits ----------

function normName(s) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

async function loadWaits() {
  if (!navigator.onLine) { waitsState = "offline"; return; }
  try {
    const res = await fetch(WAITS_URL, { cache: "no-store" });
    if (!res.ok) throw new Error("bad status");
    const data = await res.json();
    const map = new Map();
    for (const item of data.liveData || []) {
      if (item.entityType !== "ATTRACTION") continue;
      const wait = item.queue && item.queue.STANDBY ? item.queue.STANDBY.waitTime : null;
      map.set(normName(item.name), { wait, status: item.status });
    }
    waits = map;
    waitsState = "ok";
  } catch {
    waitsState = "failed";
  }
  if (plan) renderAll();
}

function waitFor(ride) {
  if (!waits || !ride) return null;
  const key = normName(ride);
  for (const [name, info] of waits) if (name.includes(key)) return info;
  return null;
}

function waitChip(ride) {
  const info = waitFor(ride);
  if (!info) return null;
  if (info.status && info.status !== "OPERATING") {
    return el("span", { class: "tag wait down" }, info.status === "DOWN" ? "Temporarily down" : "Closed now");
  }
  if (info.wait == null) return null;
  return el("span", { class: "tag wait" }, `Standby ${info.wait} min`);
}

function waitsNote() {
  const text = {
    ok: "Standby waits are live from ThemeParks.wiki.",
    offline: "Offline: live waits are not available.",
    failed: "Live waits could not be loaded.",
    idle: "",
  }[waitsState];
  return text ? el("p", { class: "meta" }, text) : null;
}

// ---------- Event cards ----------

function eventCard(ev, extra) {
  const classes = ["event", ev.type, parkClass(ev.location)];
  if (ev.status === "proposed") classes.push("proposed");
  if (isDone(ev.id)) classes.push("done");
  const badges = [];
  if (ev.status === "open") badges.push(el("span", { class: "badge open" }, "Open"));
  if (ev.status === "proposed") badges.push(el("span", { class: "badge proposed" }, "Proposed"));
  const tags = [
    ev.kid ? el("span", { class: "tag" }, ev.kid) : null,
    ev.type === "lightning" || ev.type === "attraction" ? waitChip(ev.ride) : null,
  ].filter(Boolean);
  return el("div", { class: classes.join(" ") }, [
    extra ? el("div", { class: "countdown" }, extra) : null,
    el("div", { class: "time" }, ev.time),
    el("div", { class: "title" }, [...badges, ev.title]),
    el("div", { class: "meta" }, ev.location || ""),
    el("div", { class: "grp" }, groupChips(ev.groups)),
    tags.length ? el("div", { class: "tags" }, tags) : null,
    ev.meet ? el("div", { class: "notes" }, ev.meet) : null,
    ev.notes ? el("div", { class: "notes" }, ev.notes) : null,
    ...(ev.type === "travel" ? [] : cardActions(ev.id, ev.title, ev.location)),
  ]);
}

// True while a plan is in progress: inside a Lightning Lane window, or during a meal or show.
function isActive(ev, mins) {
  if (!ev.start) return false;
  const start = minutes(ev.start);
  const until = ev.end ? minutes(ev.end) : start + Math.max(ev.dur || 0, 15);
  return mins >= start && mins <= until;
}

// Adds a day's cards to a list. On the current day a small red bar sits to the
// left of any card you should be at right now. If nothing is in progress, a red
// dot marks where the current time falls between cards.
function appendDayCards(container, day, events) {
  const now = nowET();
  if (day.date !== now.date) {
    container.append(...events.map((ev) => eventCard(ev)));
    return;
  }
  const label = clock(now.mins).replace(/ (AM|PM)$/, "");
  const anyActive = events.some((ev) => isActive(ev, now.mins));
  let placed = false;
  const gapMarker = () => el("div", { class: "now-gap" }, el("span", { class: "now-time" }, label));
  for (const ev of events) {
    if (!anyActive && !placed && ev.start && minutes(ev.start) > now.mins) {
      container.append(gapMarker());
      placed = true;
    }
    const card = eventCard(ev);
    card.classList.add("today");
    if (isActive(ev, now.mins)) {
      card.classList.add("active-now");
      // The time is written once, beside the first card in progress.
      if (!placed) card.append(el("span", { class: "now-time" }, label));
      placed = true;
    }
    container.append(card);
  }
  if (!placed) container.append(gapMarker());
}

// Sticky date header shared by the lists.
function dayHeader(label) {
  return el("h3", { class: "day-h" }, label);
}

function hoursBlock(day) {
  if (!day.hours) return null;
  return el("div", { class: "hours" }, day.hours.map((h) => el("div", {}, [
    el("span", { class: "dot p-" + parkCode(h.park) }),
    `${h.park}: ${h.hours}`,
    h.note ? el("span", { class: "hours-note" }, ` · ${h.note}`) : null,
  ])));
}

// ---------- Now and next ----------

// The trip is under way from the first day through the last, on Orlando's calendar.
function inTrip() {
  const today = nowET().date;
  return today >= plan.days[0].date && today <= plan.days[plan.days.length - 1].date;
}

// The Now tab only exists during the trip. Outside it, the Itinerary tab is the home tab.
function selectTab(name) {
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === name));
}
function syncNowTab(initial) {
  const tab = document.querySelector('.tab[data-tab="now"]');
  const show = inTrip();
  const wasHidden = tab.hidden;
  tab.hidden = !show;
  if (show && (initial || wasHidden)) selectTab("now");
  if (!show && tab.classList.contains("active")) selectTab("itinerary");
}

function renderNow() {
  const top = document.getElementById("now-top");
  const root = document.getElementById("now-list");
  groupFilter(document.getElementById("now-group-chips"));
  top.replaceChildren();
  root.replaceChildren();
  if (!inTrip()) return;
  const now = nowET();
  const day = plan.days.find((d) => d.date === now.date);
  top.append(el("div", { class: "now-banner" }, `${day.label} · ${clock(now.mins)} in Orlando`));
  const hours = hoursBlock(day);
  if (hours) top.append(hours);

  const mine = day.events.filter((ev) => matchesGroup(ev.groups, state.group));
  const current = [], next = [], anytime = [];
  for (const ev of mine) {
    if (isDone(ev.id)) continue;
    const start = minutes(ev.start);
    if (start == null) { anytime.push(ev); continue; }
    const until = ev.end ? minutes(ev.end) : start + (ev.dur || 0);
    if (now.mins < start) next.push([ev, `Starts in ${span(start - now.mins)}`]);
    else if (now.mins <= until) {
      current.push([ev, ev.end ? `Window open · closes in ${span(until - now.mins)}` : "Happening now"]);
    }
  }
  if (current.length) root.append(dayHeader("Now"), ...current.map(([ev, t]) => eventCard(ev, t)));
  if (next.length) {
    root.append(dayHeader("Up next"), eventCard(...next[0]));
    if (next.length > 1) root.append(dayHeader("Later today"), ...next.slice(1).map(([ev, t]) => eventCard(ev, t)));
  }
  if (anytime.length) root.append(dayHeader("Any time today"), ...anytime.map((ev) => eventCard(ev)));
  if (!current.length && !next.length && !anytime.length) {
    root.append(el("p", { class: "meta" }, "Nothing left on the plan today."));
  }
}

// ---------- Itinerary ----------

function renderItinerary() {
  const dayChips = document.getElementById("day-chips");
  const typeChips = document.getElementById("type-chips");
  const days = document.getElementById("days");
  groupFilter(document.getElementById("group-chips"));
  dayChips.replaceChildren();
  typeChips.replaceChildren();
  days.replaceChildren();

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
    days.append(dayHeader(d.label));
    const hours = hoursBlock(d);
    if (hours) days.append(hours);
    const warn = warningList(dayWarnings(d));
    if (warn) days.append(warn);
    appendDayCards(days, d, matches);
  }
  if (!shown) days.append(el("p", { class: "meta" }, "Nothing matches these filters."));
}

// ---------- Lightning Lanes ----------

function renderLightning() {
  const list = document.getElementById("ll-list");
  groupFilter(document.getElementById("ll-group-chips"));
  list.replaceChildren();

  let shown = 0;
  for (const d of plan.days) {
    const lanes = d.events.filter((ev) =>
      ev.type === "lightning" && matchesGroup(ev.groups, state.group));
    if (!lanes.length) continue;
    shown += lanes.length;
    list.append(dayHeader(d.label));
    appendDayCards(list, d, lanes);
  }
  if (!shown) list.append(el("p", { class: "meta" }, "No Lightning Lanes match this group."));

  const tips = document.getElementById("pass-tips");
  tips.replaceChildren(...plan.passes.map((p) => el("li", {}, p)));
}

// ---------- Dining ----------

function renderDining() {
  const list = document.getElementById("dining-list");
  groupFilter(document.getElementById("dining-group-chips"));
  list.replaceChildren();

  // Dining comes from the day events, grouped under each date header.
  let shown = 0;
  for (const d of plan.days) {
    const meals = d.events.filter((ev) => ev.type === "dining" && matchesGroup(ev.groups, state.group));
    if (!meals.length) continue;
    shown += meals.length;
    list.append(dayHeader(d.label));
    appendDayCards(list, d, meals);
  }
  if (!shown) list.append(el("p", { class: "meta" }, "No dining plans match this group."));
}

// ---------- Where is everyone ----------

const LINE_START = 8 * 60;
const LINE_END = 22 * 60;

// Park blocks for one group: each reachable stop holds its park until the next stop.
function parkBlocks(day, groupId) {
  const stops = walkDay(day, groupId).reached
    .map((r) => ({ ...r, code: parkCode(r.ev.location) || "RES" }));
  const blocks = [];
  stops.forEach((s, i) => {
    const next = stops[i + 1];
    let end = s.leave;
    if (next) end = next.code === s.code ? next.arrive : Math.max(s.leave, next.arrive - PARK_TRANSFER);
    const last = blocks[blocks.length - 1];
    if (last && last.code === s.code && last.end >= s.arrive) last.end = Math.max(last.end, end);
    else blocks.push({ code: s.code, start: s.arrive, end: Math.max(end, s.arrive + 15) });
  });
  return blocks;
}

function renderTimeline() {
  const dayChips = document.getElementById("tl-day-chips");
  const root = document.getElementById("timeline");
  dayChips.replaceChildren();
  root.replaceChildren();
  if (!state.timelineDay) {
    const today = plan.days.find((d) => d.date === nowET().date);
    state.timelineDay = (today || plan.days.find((d) => d.hours) || plan.days[0]).id;
  }
  for (const d of plan.days) {
    dayChips.append(chip(d.label, state.timelineDay === d.id, () => { state.timelineDay = d.id; renderTimeline(); }));
  }
  const day = plan.days.find((d) => d.id === state.timelineDay);
  const pct = (m) => ((Math.min(Math.max(m, LINE_START), LINE_END) - LINE_START) / (LINE_END - LINE_START)) * 100;

  // Red line at the current Orlando time, only on the day being viewed while it is today.
  const now = nowET();
  const showNow = day.date === now.date && now.mins >= LINE_START && now.mins <= LINE_END;
  const nowLine = () => (showNow ? el("div", { class: "tl-now", style: `left:${pct(now.mins)}%` }) : null);

  const axis = el("div", { class: "tl-axis" });
  for (let h = 8; h <= 22; h += 2) {
    axis.append(el("span", { style: `left:${pct(h * 60)}%` }, `${h % 12 || 12}${h < 12 ? "a" : "p"}`));
  }
  const rows = [el("div", { class: "tl-row" }, [el("div", { class: "tl-name" }), axis])];

  const perGroup = {};
  for (const g of plan.groups) {
    const blocks = parkBlocks(day, g.id);
    perGroup[g.id] = blocks;
    const lane = el("div", { class: "tl-lane" }, blocks.map((b) => el("div", {
      class: "tl-block p-" + b.code,
      style: `left:${pct(b.start)}%;width:${Math.max(pct(b.end) - pct(b.start), 2)}%`,
      title: `${clock(b.start)} – ${clock(b.end)}`,
    }, b.code === "RES" ? "Resort" : b.code)));
    lane.append(...[nowLine()].filter(Boolean));
    rows.push(el("div", { class: "tl-row" }, [el("div", { class: "tl-name" }, el("span", { class: "g " + g.id }, g.id)), lane]));
  }

  // Stretches when every group is in the same place.
  const together = [];
  let open = null;
  for (let m = LINE_START; m <= LINE_END; m += 5) {
    const codes = plan.groups.map((g) => (perGroup[g.id].find((b) => m >= b.start && m < b.end) || {}).code);
    const same = codes[0] && codes.every((c) => c === codes[0]);
    if (same && !open) open = { start: m, code: codes[0] };
    if ((!same || m === LINE_END) && open) { together.push({ ...open, end: m }); open = null; }
  }
  const tLane = el("div", { class: "tl-lane" }, together.map((b) => el("div", {
    class: "tl-block together",
    style: `left:${pct(b.start)}%;width:${Math.max(pct(b.end) - pct(b.start), 2)}%`,
  })));
  tLane.append(...[nowLine()].filter(Boolean));
  rows.push(el("div", { class: "tl-row" }, [el("div", { class: "tl-name" }, "All"), tLane]));
  if (showNow) root.append(el("p", { class: "now-label" }, `Now: ${clock(now.mins)}`));
  root.append(el("div", { class: "tl" }, rows));

  root.append(el("div", { class: "tl-legend" }, [
    ...PARKS.map(([name, code]) => el("span", {}, [el("span", { class: "dot p-" + code }), name])),
    el("span", {}, [el("span", { class: "dot together" }), "Everyone together"]),
  ]));
  root.append(together.length
    ? el("p", { class: "meta" }, "Together: " + together.map((b) => `${clock(b.start)} – ${clock(b.end)}`).join(", "))
    : el("p", { class: "meta" }, "No stretch on this day has every group in the same place."));

  const warnings = plan.groups.flatMap((g) => walkDay(day, g.id).warnings);
  const warn = warningList(warnings);
  if (warn) root.append(warn);

  root.append(el("p", { class: "meta" },
    `Blocks are estimates from the plan. They assume ${PARK_TRANSFER} minutes to change parks and ${SAME_PARK_WALK} minutes between stops in one park.`));
}

// ---------- Wish list ----------

function renderWish() {
  const root = document.getElementById("wish-list");
  root.replaceChildren();
  const note = waitsNote();
  if (note) root.append(note);
  const planned = plan.days.flatMap((d) => d.events).filter((ev) => ev.ride);

  const card = (r, park, showPark) => {
    const id = "wish-" + normName(r.name);
    const ride = r.ride || r.name;
    const inPlan = planned.find((ev) => normName(r.name).includes(normName(ev.ride)));
    const tags = [
      showPark ? el("span", { class: "tag" }, park) : null,
      el("span", { class: "tag" }, r.kid),
      r.pass ? el("span", { class: "tag" }, r.pass) : null,
      inPlan ? el("span", { class: "tag plan" }, inPlan.status === "proposed" ? "Proposed" : "In the plan") : null,
      waitChip(ride),
    ].filter(Boolean);
    return el("div", { class: "event " + parkClass(park) + (isDone(id) ? " done" : "") }, [
      el("div", { class: "title" }, r.name),
      el("div", { class: "tags" }, tags),
      ...cardActions(id, r.name, park, true),
    ]);
  };

  // Favorites are pulled out of their park and listed first.
  const all = plan.wishlist.flatMap((p) => p.rides.map((r) => ({ r, park: p.park })));
  const favs = all.filter((x) => isFav("wish-" + normName(x.r.name)));
  if (favs.length) root.append(dayHeader("Favorites"), ...favs.map((x) => card(x.r, x.park, true)));
  for (const p of plan.wishlist) {
    const rest = p.rides.filter((r) => !isFav("wish-" + normName(r.name)));
    if (!rest.length) continue;
    root.append(dayHeader(p.park), ...rest.map((r) => card(r, p.park, false)));
  }
  root.append(el("p", { class: "meta" }, "Every ride in the four parks. Tap Favorite to move a ride to the top. Check the Disney app for closures."));
}

// ---------- Calendar export ----------

function icsStamp(date, mins) {
  const d = new Date(Date.parse(date + "T00:00:00Z") + (mins + ET_OFFSET_HOURS * 60) * 60000);
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
}
function icsText(s) {
  return String(s).replace(/\\/g, "\\\\").replace(/([,;])/g, "\\$1").replace(/\n/g, "\\n");
}

function buildCalendar() {
  const lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Disney Trip Plan//EN", "CALSCALE:GREGORIAN"];
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  for (const d of plan.days) {
    for (const ev of d.events) {
      if (!ev.start || !matchesGroup(ev.groups, state.group)) continue;
      const start = minutes(ev.start);
      const end = ev.end ? minutes(ev.end) : start + Math.max(ev.dur || 0, 15);
      const who = ev.groups.length === plan.groups.length ? "Everyone" : ev.groups.join(", ");
      lines.push(
        "BEGIN:VEVENT",
        `UID:${ev.id}@disney-trip`,
        `DTSTAMP:${stamp}`,
        `DTSTART:${icsStamp(d.date, start)}`,
        `DTEND:${icsStamp(d.date, end)}`,
        `SUMMARY:${icsText(ev.title)}`,
        `LOCATION:${icsText(ev.location || "")}`,
        `DESCRIPTION:${icsText([ev.time, who, ev.meet, ev.notes].filter(Boolean).join(" · "))}`,
        "BEGIN:VALARM", "ACTION:DISPLAY", `DESCRIPTION:${icsText(ev.title)}`, "TRIGGER:-PT15M", "END:VALARM",
        "END:VEVENT",
      );
    }
  }
  lines.push("END:VCALENDAR");
  return lines.join("\r\n") + "\r\n";
}

function downloadCalendar() {
  const blob = new Blob([buildCalendar()], { type: "text/calendar" });
  const url = URL.createObjectURL(blob);
  const name = state.group === "ALL" ? "disney-trip.ics" : `disney-trip-${state.group}.ics`;
  const a = el("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
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
  const warnRoot = document.getElementById("open-warnings");
  const all = plan.days.flatMap((d) => plan.groups.flatMap((g) => walkDay(d, g.id).warnings));
  warnRoot.replaceChildren(...(all.length ? [warningList(all)] : []));
}

function renderAll() {
  renderNow();
  renderItinerary();
  renderLightning();
  renderDining();
  renderTimeline();
  renderWish();
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
      selectTab(btn.dataset.tab);
      window.scrollTo({ top: 0 });
    });
  });
  document.getElementById("search").addEventListener("input", (e) => {
    state.query = e.target.value;
    renderItinerary();
  });
  document.getElementById("add-calendar").addEventListener("click", downloadCalendar);
}

function renderDots() {
  const input = document.getElementById("passcode");
  const dots = document.getElementById("dots");
  dots.replaceChildren(...(input.value.length
    ? Array.from({ length: input.value.length }, () => el("span", { class: "filled" }))
    : [el("em", {}, "Tap to type, or use the keypad")]));
}

function wireKeypad() {
  const input = document.getElementById("passcode");
  // Typing works too: tapping the field opens the numeric keyboard on a phone.
  input.addEventListener("input", () => {
    input.value = input.value.replace(/\D/g, "").slice(0, MAX_DIGITS);
    document.getElementById("lock-error").hidden = true;
    renderDots();
  });
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
  if (state.group !== "ALL" && !plan.groups.some((g) => g.id === state.group)) state.group = "ALL";
  document.getElementById("lock").hidden = true;
  document.getElementById("app").hidden = false;
  document.getElementById("forget").hidden = false;
  renderAll();
  syncNowTab(true);
  loadWaits();
  // Keep the countdowns and live waits current while the page is open.
  // Skipped while a note or the search box is being typed in, so typing is not interrupted.
  setInterval(() => {
    const typing = /^(TEXTAREA|INPUT)$/.test((document.activeElement || {}).tagName || "");
    if (document.hidden || typing) return;
    syncNowTab(false);
    renderNow();
    renderItinerary();
    renderLightning();
    renderDining();
    renderTimeline();
  }, 30000);
  setInterval(() => { if (!document.hidden) loadWaits(); }, 5 * 60000);
}

async function loadEnc() {
  const res = await fetch(ENC_URL, { cache: "no-store" });
  if (!res.ok) throw new Error("Could not load the plan.");
  return res.json();
}

async function tryRemembered() {
  let enc;
  try {
    enc = await loadEnc();
  } catch {
    return; // Offline with nothing cached yet: stay on the passcode screen.
  }
  try {
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

// Offline support: the service worker keeps the last loaded copy of the site and plan.
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("sw.js").catch(() => { /* offline mode unavailable */ });
}

document.getElementById("unlock-form").addEventListener("submit", unlock);
document.getElementById("forget").addEventListener("click", forgetDevice);
document.getElementById("refresh").addEventListener("click", () => location.reload());
wireKeypad();
renderDots();
wireTabs();
wireTheme();
tryRemembered();
