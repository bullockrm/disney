// Client-side decryption. The plan is stored encrypted in data/plan.enc.json.
// Nothing is decrypted until the passcode is entered, and only the derived key is remembered.

const ENC_URL = "data/plan.enc.json";
const REMEMBER_KEY = "disney-plan-unlock";
const THEME_KEY = "disney-theme";
const GROUP_KEY = "disney-group";
const DONE_KEY = "disney-done";
const NOTES_KEY = "disney-notes";
const FAV_KEY = "disney-favorites";
const HINT_KEY = "disney-swipe-hint-seen";
const SWIPE_DISTANCE = 70;
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
    ["encrypt", "decrypt"]
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
  return crypto.subtle.importKey("raw", b64ToBytes(saved.key), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
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

// Note box inside a card. It stays hidden until there is a note or the card is swiped right.
function noteBox(id) {
  const box = el("textarea", { class: "note-input", rows: "2", placeholder: "Note (saved on this device)", hidden: "" });
  box.value = noteFor(id);
  if (box.value) box.hidden = false;
  box.addEventListener("change", () => saveNote(id, box.value));
  box.addEventListener("blur", () => { if (!box.value.trim()) box.hidden = true; });
  return box;
}

function swipeHint() {
  if (readStore(HINT_KEY, false)) return null;
  return el("p", { class: "hint" }, "Tap a card for directions · swipe left for Done · swipe right for a note · hold to edit");
}

// Wraps a card so it can be swiped: left marks it done, right opens its note,
// and a plain tap opens directions. Vertical scrolling is left to the browser.
function swipeCard(card, opts) {
  const wrap = el("div", { class: "swipe" }, [
    el("div", { class: "swipe-bg", "aria-hidden": "true" }, [
      el("span", { class: "swipe-note" }, "✎ Note"),
      el("span", { class: "swipe-done" }, opts && isDone(opts.id) ? "↺ Not done" : "✓ Done"),
    ]),
    card,
  ]);
  if (!opts) return wrap;
  card.classList.add("swipeable");

  let x0 = null, y0 = 0, dx = 0, dragging = false, moved = false, pid = null, suppressClick = false;
  let holdTimer = null;
  const cancelHold = () => { clearTimeout(holdTimer); holdTimer = null; };
  const reset = () => {
    cancelHold();
    wrap.classList.remove("dragging", "armed");
    card.style.transform = "";
    x0 = null; dragging = false; dx = 0;
  };
  card.addEventListener("pointerdown", (e) => {
    suppressClick = false;
    if (e.target.closest("textarea, button, a, input")) return;
    if (e.pointerType === "mouse" && e.button !== 0) return;
    x0 = e.clientX; y0 = e.clientY; dx = 0; dragging = false; moved = false; pid = e.pointerId;
    if (opts.onEdit) {
      cancelHold();
      // Press and hold opens the edit sheet.
      holdTimer = setTimeout(() => {
        holdTimer = null;
        if (moved || dragging) return;
        x0 = null;
        suppressClick = true;
        if (navigator.vibrate) navigator.vibrate(10);
        opts.onEdit();
      }, 500);
    }
  });
  card.addEventListener("pointermove", (e) => {
    if (x0 === null || e.pointerId !== pid) return;
    const mx = e.clientX - x0;
    const my = e.clientY - y0;
    if (!dragging) {
      if (Math.abs(mx) < 8 && Math.abs(my) < 8) return;
      moved = true;
      cancelHold();
      if (Math.abs(my) > Math.abs(mx)) { x0 = null; return; } // a scroll, not a swipe
      dragging = true;
      try { card.setPointerCapture(pid); } catch { /* pointer already released */ }
      wrap.classList.add("dragging");
    }
    dx = Math.max(-130, Math.min(130, mx));
    card.style.transform = `translateX(${dx}px)`;
    wrap.dataset.dir = dx > 0 ? "note" : "done";
    wrap.classList.toggle("armed", Math.abs(dx) >= SWIPE_DISTANCE);
  });
  card.addEventListener("pointerup", () => {
    cancelHold();
    if (moved) suppressClick = true;
    if (!dragging) { x0 = null; return; }
    const action = dx <= -SWIPE_DISTANCE ? "done" : dx >= SWIPE_DISTANCE ? "note" : null;
    reset();
    if (!action) return;
    writeStore(HINT_KEY, true);
    document.querySelectorAll(".hint").forEach((h) => h.remove());
    if (action === "done") {
      toggleDone(opts.id);
      renderAll();
    } else {
      const box = card.querySelector(".note-input");
      box.hidden = false;
      box.focus();
    }
  });
  card.addEventListener("pointercancel", reset);
  card.addEventListener("contextmenu", (e) => { if (opts.onEdit) e.preventDefault(); });
  card.addEventListener("click", (e) => {
    if (suppressClick) { suppressClick = false; return; }
    if (e.target.closest("textarea, button, a, input")) return;
    if (opts.location) window.open(mapsUrl(opts.name, opts.location), "_blank", "noopener");
  });
  return wrap;
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
    return el("span", { class: "tag wait down" }, info.status === "DOWN" ? "Down" : "Closed");
  }
  if (info.wait == null) return null;
  return el("span", { class: "tag wait", title: "Current standby wait" }, `${info.wait} min wait`);
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

// Small line icons for each kind of plan, covering the same subjects the Disney
// itinerary uses: dining, Lightning Lanes, parades, fireworks, the resort and travel.
const ICONS = {
  lightning: '<path d="M15.5 2 8 13h5.5l-1.5 9 8.5-12.5H15z" fill="currentColor" stroke="none"/><path d="M2.5 8.5h4.5M1.5 12.5h4.5M3 16.5h4"/>',
  dining: '<path d="M6 2v7.5M3.5 2v5a2.5 2.5 0 0 0 5 0V2M6 9.5V22M17.5 22V2c-2.6 1.3-3.9 4.4-3.9 8.6V14h3.9"/>',
  parade: '<ellipse cx="12" cy="9.5" rx="8" ry="3"/><path d="M4 9.5v7c0 1.7 3.6 3 8 3s8-1.3 8-3v-7M8 12.3v7M16 12.3v7M8.5 2.5l3 5M15.5 2.5l-3 5"/>',
  fireworks: '<circle cx="12" cy="12" r="1.6" fill="currentColor"/><path d="M12 2.5v4M12 17.5v4M2.5 12h4M17.5 12h4M5.3 5.3l2.8 2.8M15.9 15.9l2.8 2.8M5.3 18.7l2.8-2.8M15.9 8.1l2.8-2.8"/>',
  ride: '<path d="M2.5 18.5C5 10 7 6.5 9.5 6.5s3.5 7 6 7 3.4-3 6-6.5M2 18.5h20M6 18.5v-6M10 18.5V7M15.5 18.5v-5"/>',
  plane: '<path d="M21 15.5v-2l-8-5V3.5a1.5 1.5 0 0 0-3 0v5l-8 5v2l8-2.5v5.5l-2 1.5V22l3.5-1 3.5 1v-1.5l-2-1.5V13z" fill="currentColor" stroke="none"/>',
  bus: '<rect x="4" y="3" width="16" height="14.5" rx="2.5"/><path d="M4 11h16M7.5 17.5V21M16.5 17.5V21"/><circle cx="8" cy="14.3" r="1" fill="currentColor"/><circle cx="16" cy="14.3" r="1" fill="currentColor"/>',
  resort: '<path d="M4.5 21V10.5h15V21M2.5 21h19M10 21v-4h4v4M12 10.5V3l5 1.8L12 6.6M8 13.5h1.5M14.5 13.5H16"/>',
};

function iconFor(ev) {
  const t = ev.title.toLowerCase();
  if (/parade/.test(t)) return "parade";
  if (/happily ever after|luminous|fantasmic|fireworks|nighttime/.test(t)) return "fireworks";
  if (ev.type === "lightning") return "lightning";
  if (ev.type === "dining") return "dining";
  if (ev.type === "show") return /parade/.test(t) ? "parade" : "fireworks";
  if (ev.type === "travel") {
    if (/mears|bus|shuttle/.test(t)) return "bus";
    if (/check|resort|room/.test(t)) return "resort";
    return "plane";
  }
  return "ride";
}

function iconEl(name) {
  const span = el("span", { class: "ev-icon", "aria-hidden": "true" });
  span.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>`;
  return span;
}

function eventCard(ev, extra) {
  const classes = ["event", ev.type, parkClass(ev.location)];
  if (ev.status === "proposed") classes.push("proposed");
  if (isDone(ev.id)) classes.push("done");
  const right = [
    ev.status === "open" ? el("span", { class: "badge open" }, "Open") : null,
    ev.status === "proposed" ? el("span", { class: "badge proposed" }, "Proposed") : null,
    isDone(ev.id) ? el("span", { class: "badge done" }, "✓ Done") : null,
    ev.type === "lightning" || ev.type === "attraction" ? waitChip(ev.ride) : null,
  ].filter(Boolean);
  const travel = ev.type === "travel";
  const card = el("div", { class: classes.join(" ") }, [
    extra ? el("div", { class: "countdown" }, extra) : null,
    el("div", { class: "time-row" }, [
      el("span", { class: "time" }, [iconEl(iconFor(ev)), ev.time]),
      right.length ? el("span", { class: "status" }, right) : null,
    ]),
    el("div", { class: "title" }, ev.title),
    el("div", { class: "meta" }, ev.location || ""),
    el("div", { class: "grp" }, groupChips(ev.groups)),
    ev.meet ? el("div", { class: "notes" }, ev.meet) : null,
    ev.notes ? el("div", { class: "notes" }, ev.notes) : null,
    noteBox(ev.id),
  ]);
  return swipeCard(card, {
    id: ev.id, name: ev.title, location: travel ? null : ev.location,
    onEdit: () => openEditor(ev.id),
  });
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
function dayHeader(label, addDayId) {
  if (!addDayId) return el("h3", { class: "day-h" }, label);
  const add = el("button", { type: "button", class: "day-add", "aria-label": "Add to " + label }, "+ Add");
  add.addEventListener("click", () => openEditor(null, addDayId));
  return el("h3", { class: "day-h" }, [el("span", {}, label), add]);
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

// The day picked on the Now tab. It starts on today, or the first park day before the trip.
function selectedDay() {
  if (!state.timelineDay) {
    const today = plan.days.find((d) => d.date === nowET().date);
    state.timelineDay = (today || plan.days.find((d) => d.hours) || plan.days[0]).id;
  }
  return state.timelineDay;
}

function renderNow() {
  const top = document.getElementById("now-top");
  const root = document.getElementById("now-list");
  groupFilter(document.getElementById("now-group-chips"));
  top.replaceChildren();
  root.replaceChildren();
  if (!inTrip()) return;
  const hint = swipeHint();
  if (hint) top.append(hint);
  const now = nowET();
  const day = plan.days.find((d) => d.id === selectedDay());
  const isToday = day.date === now.date;
  top.append(el("div", { class: "now-banner" },
    isToday ? `${day.label} · ${clock(now.mins)} in Orlando` : day.label));
  const hours = hoursBlock(day);
  if (hours) top.append(hours);

  // Another day picked: show that day's plan instead of now and next.
  if (!isToday) {
    const events = day.events.filter((ev) => matchesGroup(ev.groups, state.group));
    root.append(dayHeader(day.label));
    if (events.length) appendDayCards(root, day, events);
    else root.append(el("p", { class: "meta" }, "Nothing planned for this group."));
    return;
  }

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

  const hint = swipeHint();
  if (hint) days.append(hint);
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
    days.append(dayHeader(d.label, d.id));
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
  const hint = swipeHint();
  if (hint) list.append(hint);

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
  const hint = swipeHint();
  if (hint) list.append(hint);

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
  selectedDay();
  for (const d of plan.days) {
    dayChips.append(chip(d.label, state.timelineDay === d.id, () => {
      state.timelineDay = d.id;
      renderNow();
      renderTimeline();
    }));
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
  const root = document.getElementById("attractions-list");
  root.replaceChildren();
  const hint = swipeHint();
  if (hint) root.append(hint);
  const note = waitsNote();
  if (note) root.append(note);
  const planned = plan.days.flatMap((d) => d.events.filter((ev) => ev.ride).map((ev) => ({ ev, day: d })));

  const card = (r, park, showPark) => {
    const id = "wish-" + normName(r.name);
    const ride = r.ride || r.name;
    // Every booking of this ride, with the groups that have it and the day.
    const bookings = planned.filter((x) => normName(r.name).includes(normName(x.ev.ride)));
    const star = el("button", {
      type: "button", class: "fav-star" + (isFav(id) ? " on" : ""),
      "aria-pressed": String(isFav(id)), "aria-label": "Favorite",
    }, isFav(id) ? "★" : "☆");
    star.addEventListener("click", () => { toggleFav(id); renderWish(); });
    const detail = [showPark ? park : null, r.kid, r.about, r.pass].filter(Boolean).join(" · ");
    const body = el("div", { class: "event " + parkClass(park) + (isDone(id) ? " done" : "") }, [
      el("div", { class: "title-row" }, [
        el("span", { class: "title" }, r.name),
        el("span", { class: "status" }, [
          isDone(id) ? el("span", { class: "badge done" }, "✓ Done") : null,
          waitChip(ride),
          star,
        ].filter(Boolean)),
      ]),
      el("div", { class: "meta" }, detail),
      ...bookings.map((x) => el("div", { class: "booked" }, [
        el("span", { class: "booked-label" }, x.ev.status === "proposed" ? "Proposed for" : "In the plan for"),
        ...groupChips(x.ev.groups),
        el("span", {}, `${x.day.label} · ${x.ev.time}`),
      ])),
      noteBox(id),
    ]);
    return swipeCard(body, { id, name: r.name, location: park });
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
  root.append(el("p", { class: "meta" }, "Every ride in the four parks. Tap ☆ to move a ride to the top. Check the Disney app for closures."));
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

// ---------- Advice ----------
// Everything here is worked out from the current plan, so it updates with every edit.

const OPEN_STRETCH = 150; // minutes of nothing planned worth pointing out

function parkHours(day, code) {
  const h = (day.hours || []).find((x) => parkCode(x.park) === code);
  if (!h) return null;
  const [a, b] = h.hours.split(/\s[–-]\s/);
  return { name: h.park, open: minutes(to24(a)), close: minutes(to24(b)) };
}

function parkName(code) {
  return (PARKS.find(([, c]) => c === code) || [code])[0];
}

// A few rides in a park that this group doesn't already have that day: starred ones
// first, then shortest live wait.
function rideIdeas(day, groupId, code) {
  const park = plan.wishlist.find((p) => parkCode(p.park) === code);
  if (!park) return [];
  const have = day.events.filter((ev) => ev.ride && ev.groups.includes(groupId)).map((ev) => normName(ev.ride));
  return park.rides
    .filter((r) => !have.some((h) => normName(r.name).includes(h)))
    .map((r) => ({ r, fav: isFav("wish-" + normName(r.name)), wait: (waitFor(r.ride || r.name) || {}).wait }))
    .sort((a, b) => (b.fav - a.fav) || ((a.wait ?? 999) - (b.wait ?? 999)))
    .slice(0, 3)
    .map((x) => x.r.name + (x.wait != null ? ` (${x.wait} min)` : ""));
}

function buildAdvice() {
  const items = [];
  const add = (level, groups, day, text, detail) => items.push({ level, groups, day, text, detail });

  for (const day of plan.days) {
    for (const g of plan.groups) {
      // Stops that can't be reached in time.
      const { reached, warnings } = walkDay(day, g.id);
      for (const w of warnings) {
        add("warn", [g.id], day,
          `Can't make ${w.ev.title} (${w.ev.time}) after ${w.prev.title}.`,
          `${w.prev.location} to ${w.ev.location}. Earliest arrival is about ${clock(w.arrive)}.`);
      }

      // Long stretches with nothing planned during park hours.
      const parkStops = reached.filter((r) => parkCode(r.ev.location));
      const stretch = (from, to, code, label) => {
        if (to - from < OPEN_STRETCH) return;
        const ideas = rideIdeas(day, g.id, code);
        add("tip", [g.id], day,
          `${span(to - from)} open at ${parkName(code)}, ${label} ${clock(from)} – ${clock(to)}.`,
          ideas.length ? "Ideas: " + ideas.join(", ") : null);
      };
      // Only gaps between plans: before the first and after the last are left alone.
      parkStops.forEach((r, i) => {
        const next = parkStops[i + 1];
        if (!next) return;
        const code = parkCode(r.ev.location);
        const gapEnd = next.arrive - (parkCode(next.ev.location) === code ? 0 : PARK_TRANSFER);
        stretch(r.leave, gapEnd, code, "from");
      });

      // A park day with no timed plans for this group.
      const parkDay = day.events.find((ev) => !ev.start && ev.groups.includes(g.id) && parkCode(ev.location));
      if (!parkStops.length && parkDay) {
        const code = parkCode(parkDay.location);
        const ideas = rideIdeas(day, g.id, code);
        add("tip", [g.id], day, `No timed plans at ${parkName(code)} yet.`,
          ideas.length ? "Ideas: " + ideas.join(", ") : null);
      }
    }

    for (const ev of day.events) {
      // Plans outside a park's hours.
      const code = parkCode(ev.location);
      const hours = code && ev.start ? parkHours(day, code) : null;
      if (hours) {
        const start = minutes(ev.start);
        const until = ev.end ? minutes(ev.end) : start + (ev.dur || 0);
        if (start < hours.open) {
          add("warn", ev.groups, day, `${ev.title} (${ev.time}) is before ${hours.name} opens at ${clock(hours.open)}.`);
        } else if (ev.type !== "show" && until > hours.close) {
          add("warn", ev.groups, day, `${ev.title} (${ev.time}) runs past ${hours.name}'s ${clock(hours.close)} close.`);
        }
      }
      // Not booked yet.
      if (ev.status === "proposed" || ev.status === "open") {
        add("info", ev.groups, day, ev.title.replace(/\s*\(proposed[^)]*\)/i, ""),
          [ev.status === "proposed" ? "Proposed, not booked yet" : "Still open", ev.time].filter(Boolean).join(" · "));
      }
    }
  }

  // Starred rides that need a separate purchase.
  for (const p of plan.wishlist) {
    for (const r of p.rides) {
      if (r.pass && isFav("wish-" + normName(r.name))) {
        add("tip", plan.groups.map((g) => g.id), null,
          `You starred ${r.name}. Its Lightning Lane is a Single Pass, bought separately from Multi Pass.`);
      }
    }
  }

  const edited = Object.keys({ ...remoteEdits, ...pendingEdits }).length;
  if (edited) {
    add("info", plan.groups.map((g) => g.id), null,
      `${edited} item${edited > 1 ? "s have" : " has"} been changed from the original plan.`,
      "Remember to make the same changes in the Disney app. Undo all edits is in the footer.");
  }
  // The same advice for several groups is shown once, with all their chips.
  const merged = [];
  for (const x of items) {
    const same = merged.find((m) => m.level === x.level && m.day === x.day && m.text === x.text && m.detail === x.detail);
    if (same) same.groups = [...new Set([...same.groups, ...x.groups])];
    else merged.push({ ...x, groups: [...x.groups] });
  }
  const order = (g) => plan.groups.findIndex((x) => x.id === g);
  merged.forEach((m) => m.groups.sort((a, b) => order(a) - order(b)));
  return merged;
}

function renderOpen() {
  const root = document.getElementById("advice");
  groupFilter(document.getElementById("advice-group-chips"));
  root.replaceChildren();
  const all = buildAdvice();
  const items = all.filter((x) => matchesGroup(x.groups, state.group));

  const count = all.filter((x) => x.level === "warn").length;
  const badge = document.getElementById("advice-count");
  badge.textContent = String(count);
  badge.hidden = !count;

  const sections = [
    ["warn", "Needs attention"],
    ["info", "Not booked or changed"],
    ["tip", "Open time and ideas"],
  ];
  if (!items.some((x) => x.level === "warn")) {
    root.append(el("div", { class: "advice-ok" }, "✓ No timing or park-hours problems in the plan."));
  }
  for (const [level, heading] of sections) {
    const list = items.filter((x) => x.level === level);
    if (!list.length) continue;
    root.append(dayHeader(heading));
    for (const x of list) {
      root.append(el("div", { class: "advice-item " + level }, [
        el("div", { class: "advice-head" }, [
          ...(x.groups.length === plan.groups.length ? [] : groupChips(x.groups)),
          x.day ? el("span", { class: "advice-day" }, x.day.label) : null,
        ]),
        el("div", { class: "advice-text" }, x.text),
        x.detail ? el("div", { class: "meta" }, x.detail) : null,
      ]));
    }
  }
  root.append(el("p", { class: "meta" },
    `Worked out from the current plan, assuming ${PARK_TRANSFER} minutes to change parks and ${SAME_PARK_WALK} minutes between stops in a park.`));
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

// ---------- Shared edits ----------
// The GitHub file is the original plan. Edits are stored separately in Firebase as an
// encrypted overlay keyed by event id, so different people's edits merge, and the
// original can be restored. Edits not yet saved (offline) wait on this device.

const FIREBASE_CONFIG = {
  apiKey: "AIzaSyBDl6nHDae2U5CyYbQU_Z77w6SHrDVW__A",
  authDomain: "disney-2026-1447e.firebaseapp.com",
  projectId: "disney-2026-1447e",
  storageBucket: "disney-2026-1447e.firebasestorage.app",
  messagingSenderId: "363822465088",
  appId: "1:363822465088:web:e97984a0964d914dc9dfa5",
};
const PENDING_KEY = "disney-pending-edits";
const EVENT_TYPES = [
  ["lightning", "Lightning Lane"],
  ["dining", "Dining"],
  ["show", "Show"],
  ["attraction", "Attraction"],
  ["travel", "Travel"],
];
const PLACES = ["Magic Kingdom", "EPCOT", "Hollywood Studios", "Animal Kingdom", "Caribbean Beach Resort"];
const DEFAULT_DUR = { lightning: 20, dining: 75, show: 20, attraction: 30, travel: 0 };

let basePlan = null;
let planKey = null;
let remoteEdits = {};
let pendingEdits = readStore(PENDING_KEY, {});
let fb = null;
let syncRef = null;
let syncState = "connecting";
let flushing = false;

function bytesToB64(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

// Same format as the GitHub file: ciphertext and tag stored separately.
async function encryptWithKey(key, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(value))));
  return {
    v: 1,
    iv: bytesToB64(iv),
    tag: bytesToB64(sealed.slice(sealed.length - 16)),
    data: bytesToB64(sealed.slice(0, sealed.length - 16)),
  };
}

// Builds the plan shown on screen: the original plan with every edit applied.
function applyEdits(base, edits) {
  const p = structuredClone(base);
  const order = new Map();
  p.days.forEach((d) => d.events.forEach((ev, i) => order.set(ev.id, i)));
  for (const d of p.days) d.events = d.events.filter((ev) => !edits[ev.id]);
  for (const [id, ev] of Object.entries(edits)) {
    if (ev.deleted) continue;
    const day = p.days.find((d) => d.id === ev.day) || p.days[0];
    day.events.push({ ...ev, id });
  }
  for (const d of p.days) {
    d.events.sort((a, b) =>
      (a.start || "00:00").localeCompare(b.start || "00:00") || (order.get(a.id) ?? 99) - (order.get(b.id) ?? 99));
  }
  return p;
}

function rebuildPlan() {
  plan = applyEdits(basePlan, { ...remoteEdits, ...pendingEdits });
}

function editorOpen() {
  return !document.getElementById("editor").hidden;
}

function refreshViews() {
  rebuildPlan();
  renderAll();
  renderSyncStatus();
}

function renderSyncStatus() {
  const waiting = Object.keys(pendingEdits).length;
  const text = {
    connecting: "Connecting…",
    synced: waiting ? "Saving…" : "✓ Edits synced",
    saving: "Saving…",
    offline: waiting ? `Offline · ${waiting} edit${waiting > 1 ? "s" : ""} waiting` : "Offline",
    error: waiting ? `Sync unavailable · ${waiting} edit${waiting > 1 ? "s" : ""} waiting` : "Sync unavailable",
  }[syncState];
  const node = document.getElementById("sync-status");
  node.textContent = text;
  node.className = "sync-status " + syncState;
}

async function startSync() {
  renderSyncStatus();
  if (!basePlan.sync_id) { syncState = "error"; renderSyncStatus(); return; }
  try {
    fb = await import("./vendor/firebase.js?v=1");
    const app = fb.initializeApp(FIREBASE_CONFIG);
    let db;
    try {
      db = fb.initializeFirestore(app, {
        localCache: fb.persistentLocalCache({ tabManager: fb.persistentMultipleTabManager() }),
      });
    } catch {
      db = fb.initializeFirestore(app, { localCache: fb.memoryLocalCache() });
    }
    syncRef = fb.doc(db, "plans", basePlan.sync_id);
    fb.onSnapshot(syncRef, { includeMetadataChanges: true }, async (snap) => {
      try {
        remoteEdits = snap.exists() ? (await decryptWithKey(planKey, snap.data())).events || {} : {};
      } catch {
        remoteEdits = {};
      }
      syncState = snap.metadata.fromCache ? "offline" : "synced";
      refreshViews();
      flushEdits();
    }, () => {
      syncState = "error";
      renderSyncStatus();
    });
  } catch {
    syncState = "error";
    renderSyncStatus();
  }
}

// Sends edits waiting on this device. Each save reads the latest shared edits and
// merges into them, so edits to different items from different phones all survive.
async function flushEdits() {
  if (!syncRef || flushing || !Object.keys(pendingEdits).length) return;
  flushing = true;
  const sending = structuredClone(pendingEdits);
  try {
    if (syncState !== "offline") { syncState = "saving"; renderSyncStatus(); }
    await withTimeout(fb.runTransaction(syncRef.firestore, async (tx) => {
      const snap = await tx.get(syncRef);
      const current = snap.exists() ? (await decryptWithKey(planKey, snap.data())).events || {} : {};
      const sealed = await encryptWithKey(planKey, { events: { ...current, ...sending } });
      tx.set(syncRef, { ...sealed, updated: fb.serverTimestamp() });
    }), 15000);
    for (const [id, ev] of Object.entries(sending)) {
      if (JSON.stringify(pendingEdits[id]) === JSON.stringify(ev)) delete pendingEdits[id];
    }
    writeStore(PENDING_KEY, pendingEdits);
    syncState = "synced";
  } catch {
    syncState = navigator.onLine ? "error" : "offline";
  } finally {
    flushing = false;
    renderSyncStatus();
  }
}

// A save that can't reach the server gives up after a while and is retried later.
function withTimeout(promise, ms) {
  return Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms))]);
}

function saveEdit(id, value) {
  pendingEdits[id] = value;
  writeStore(PENDING_KEY, pendingEdits);
  refreshViews();
  flushEdits();
}

async function resetEdits() {
  pendingEdits = {};
  writeStore(PENDING_KEY, pendingEdits);
  if (syncRef) {
    try {
      const sealed = await encryptWithKey(planKey, { events: {} });
      await withTimeout(fb.runTransaction(syncRef.firestore, async (tx) => {
        await tx.get(syncRef);
        tx.set(syncRef, { ...sealed, updated: fb.serverTimestamp() });
      }), 15000);
      remoteEdits = {};
    } catch {
      syncState = "error";
    }
  }
  refreshViews();
}

window.addEventListener("online", flushEdits);
setInterval(flushEdits, 30000);

// ---------- Edit sheet ----------

function to24(text) {
  const m = (text || "").match(/(\d{1,2}):(\d{2})\s*(AM|PM)/i);
  if (!m) return "";
  let h = +m[1] % 12;
  if (/pm/i.test(m[3])) h += 12;
  return String(h).padStart(2, "0") + ":" + m[2];
}

function timeLabel(start, end, second, fallback) {
  if (!start) return fallback || "Any time";
  const a = clock(minutes(start));
  if (end) return `${a} – ${clock(minutes(end))}`;
  if (second) {
    const b = clock(minutes(second));
    return a.slice(-2) === b.slice(-2) ? `${a.slice(0, -3)} / ${b}` : `${a} / ${b}`;
  }
  return a;
}

function field(label, input, cls) {
  return el("label", { class: "ed-field" + (cls ? " " + cls : "") }, [el("span", {}, label), input]);
}

// Opens the edit sheet for an existing item, or a blank one for a new item on a day.
function openEditor(eventId, dayId) {
  const sheet = document.getElementById("editor");
  const day = plan.days.find((d) => d.events.some((ev) => ev.id === eventId)) || plan.days.find((d) => d.id === dayId);
  const original = day.events.find((ev) => ev.id === eventId);
  const ev = original || {
    title: "", type: "attraction", location: "", notes: "",
    groups: state.group === "ALL" ? plan.groups.map((g) => g.id) : [state.group],
  };
  const id = eventId || "x-" + crypto.getRandomValues(new Uint32Array(2)).join("");
  const split = (ev.time || "").includes(" / ");

  const title = el("input", { type: "text", required: "" }); title.value = ev.title;
  const daySel = el("select", {}, plan.days.map((d) => el("option", { value: d.id }, d.label)));
  daySel.value = day.id;
  const typeSel = el("select", {}, EVENT_TYPES.map(([v, t]) => el("option", { value: v }, t)));
  typeSel.value = ev.type;
  const start = el("input", { type: "time" }); start.value = ev.start || "";
  const end = el("input", { type: "time" });
  end.value = ev.end || (ev.start && ev.dur ? clockTo24(minutes(ev.start) + ev.dur) : "");
  const second = el("input", { type: "time" }); second.value = split ? to24(ev.time.split(" / ")[1]) : "";
  if (split) end.value = "";
  const loc = el("input", { type: "text", list: "ed-places" }); loc.value = ev.location || "";
  const places = el("datalist", { id: "ed-places" }, PLACES.map((p) => el("option", { value: p })));
  const rides = plan.wishlist.flatMap((p) => p.rides.map((r) => r.ride || r.name));
  const rideSel = el("select", {}, [el("option", { value: "" }, "None"),
    ...plan.wishlist.flatMap((p) => p.rides.map((r) => el("option", { value: r.ride || r.name }, r.name)))]);
  rideSel.value = rides.includes(ev.ride) ? ev.ride : "";
  const notes = el("textarea", { rows: "2" }); notes.value = ev.notes || "";
  const proposed = el("input", { type: "checkbox" }); proposed.checked = ev.status === "proposed";
  const groupBoxes = plan.groups.map((g) => {
    const box = el("input", { type: "checkbox", value: g.id });
    box.checked = ev.groups.includes(g.id) || ev.groups.includes("ALL");
    return el("label", { class: "ed-group" }, [box, el("span", { class: "g " + g.id }, g.id)]);
  });
  const error = el("p", { class: "ed-error", hidden: "" });

  const endField = field("Ends", end);
  const secondField = field("Second seating", second);
  const rideField = field("Ride (for wait times and Attractions)", rideSel);
  const syncFields = () => {
    const t = typeSel.value;
    endField.firstChild.textContent = t === "lightning" ? "Window ends" : "Ends";
    secondField.hidden = t !== "dining";
    rideField.hidden = !(t === "lightning" || t === "attraction");
  };
  typeSel.addEventListener("change", syncFields);
  syncFields();

  const close = () => { sheet.hidden = true; sheet.replaceChildren(); };
  const save = () => {
    const groups = groupBoxes.map((l) => l.firstChild).filter((b) => b.checked).map((b) => b.value);
    if (!title.value.trim()) { error.textContent = "Add a title."; error.hidden = false; return; }
    if (!groups.length) { error.textContent = "Pick at least one group."; error.hidden = false; return; }
    if (end.value && start.value && end.value <= start.value) {
      error.textContent = "The end time must be after the start."; error.hidden = false; return;
    }
    const t = typeSel.value;
    const lane = t === "lightning" && end.value;
    const twoSeatings = t === "dining" && second.value && !end.value;
    const next = {
      ...(original || {}),
      day: daySel.value,
      title: title.value.trim(),
      type: t,
      groups,
      location: loc.value.trim(),
      notes: notes.value.trim(),
      start: start.value || null,
      end: lane ? end.value : null,
      dur: !lane && start.value && end.value ? minutes(end.value) - minutes(start.value) : (original && original.type === t ? original.dur : DEFAULT_DUR[t]),
      time: timeLabel(start.value, lane ? end.value : null, twoSeatings ? second.value : null,
        !start.value && original ? original.time : null),
      ride: rideField.hidden ? null : rideSel.value || null,
    };
    if (!lane && t !== "lightning" && end.value) next.time = timeLabel(start.value, end.value, null);
    if (proposed.checked) next.status = "proposed"; else delete next.status;
    delete next.id;
    close();
    saveEdit(id, next);
  };

  const buttons = [
    original ? el("button", { type: "button", class: "ed-btn danger" }, "Delete") : null,
    el("span", { class: "ed-spacer" }),
    el("button", { type: "button", class: "ed-btn" }, "Cancel"),
    el("button", { type: "button", class: "ed-btn primary" }, "Save"),
  ].filter(Boolean);
  const [del] = original ? buttons : [null];
  if (del) {
    del.addEventListener("click", () => {
      if (del.dataset.armed) { close(); saveEdit(id, { deleted: true, day: day.id }); return; }
      del.dataset.armed = "1";
      del.textContent = "Tap again to delete";
    });
  }
  buttons[buttons.length - 2].addEventListener("click", close);
  buttons[buttons.length - 1].addEventListener("click", save);

  const panel = el("div", { class: "ed-panel", role: "dialog", "aria-modal": "true", "aria-label": original ? "Edit plan item" : "Add plan item" }, [
    el("h2", {}, original ? "Edit" : "Add to " + day.label),
    field("Title", title),
    el("div", { class: "ed-row" }, [field("Day", daySel), field("Type", typeSel)]),
    el("div", { class: "ed-row" }, [field("Starts", start), endField, secondField]),
    el("div", { class: "ed-field" }, [el("span", {}, "Groups"), el("div", { class: "ed-groups" }, groupBoxes)]),
    field("Location", loc),
    places,
    rideField,
    field("Notes", notes),
    el("label", { class: "ed-check" }, [proposed, " Proposed, not booked yet"]),
    error,
    el("p", { class: "ed-meta" }, "Changes go to everyone's phones. They don't change anything in the Disney app."),
    el("div", { class: "ed-buttons" }, buttons),
  ]);
  sheet.replaceChildren(el("div", { class: "ed-backdrop" }), panel);
  sheet.firstChild.addEventListener("click", close);
  sheet.hidden = false;
  if (!original) title.focus();
}

function clockTo24(mins) {
  return String(Math.floor(mins / 60) % 24).padStart(2, "0") + ":" + String(mins % 60).padStart(2, "0");
}

function openResetConfirm() {
  const sheet = document.getElementById("editor");
  const count = Object.keys({ ...remoteEdits, ...pendingEdits }).length;
  const cancel = el("button", { type: "button", class: "ed-btn" }, "Cancel");
  const go = el("button", { type: "button", class: "ed-btn danger" }, "Undo all edits");
  const close = () => { sheet.hidden = true; sheet.replaceChildren(); };
  cancel.addEventListener("click", close);
  go.addEventListener("click", () => { close(); resetEdits(); });
  sheet.replaceChildren(el("div", { class: "ed-backdrop" }), el("div", { class: "ed-panel", role: "dialog", "aria-modal": "true" }, [
    el("h2", {}, "Undo all edits?"),
    el("p", {}, count
      ? `This removes ${count} edit${count > 1 ? "s" : ""} for everyone and puts back the original plan. It can't be undone.`
      : "There are no edits to undo."),
    el("div", { class: "ed-buttons" }, [el("span", { class: "ed-spacer" }), cancel, count ? go : null].filter(Boolean)),
  ]));
  sheet.firstChild.addEventListener("click", close);
  sheet.hidden = false;
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

// Dark mode works with every theme. It follows the phone's setting until toggled.
const MODE_KEY = "disney-mode";
function applyMode(dark) {
  if (dark) document.documentElement.dataset.mode = "dark";
  else delete document.documentElement.dataset.mode;
  const btn = document.getElementById("mode-toggle");
  btn.setAttribute("aria-pressed", String(dark));
  btn.textContent = dark ? "☀" : "☾";
  btn.setAttribute("aria-label", dark ? "Light mode" : "Dark mode");
}
function wireMode() {
  applyMode(document.documentElement.dataset.mode === "dark");
  document.getElementById("mode-toggle").addEventListener("click", () => {
    const dark = document.documentElement.dataset.mode !== "dark";
    applyMode(dark);
    try { localStorage.setItem(MODE_KEY, dark ? "dark" : "light"); } catch { /* storage unavailable */ }
  });
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

function showPlan(decrypted, key) {
  basePlan = decrypted;
  planKey = key;
  rebuildPlan();
  if (state.group !== "ALL" && !plan.groups.some((g) => g.id === state.group)) state.group = "ALL";
  document.getElementById("lock").hidden = true;
  document.getElementById("app").hidden = false;
  document.getElementById("forget").hidden = false;
  renderAll();
  syncNowTab(true);
  loadWaits();
  startSync();
  // Keep the countdowns and live waits current while the page is open.
  // Skipped while a note or the search box is being typed in, so typing is not interrupted.
  setInterval(() => {
    const typing = /^(TEXTAREA|INPUT)$/.test((document.activeElement || {}).tagName || "");
    if (document.hidden || typing || editorOpen() || document.querySelector(".swipe.dragging")) return;
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
    showPlan(await decryptWithKey(key, enc), key);
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
    showPlan(decrypted, key);
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
document.getElementById("reset-edits").addEventListener("click", openResetConfirm);
wireKeypad();
renderDots();
wireTabs();
wireTheme();
wireMode();
tryRemembered();
