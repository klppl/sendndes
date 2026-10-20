"use strict";
// send n*des project site: Aster mascot, the travelling ticket, and the copy button. Everything works without it.
(() => {
  const SVGNS = "http://www.w3.org/2000/svg";
  const s = (tag, attrs, ...kids) => {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
    for (const kid of kids.flat()) if (kid) el.append(kid);
    return el;
  };

  // Aster: same geometry as the Mac app (app/Sources/sendndes/Mascot.swift) and the server page.
  function heartPath(cx, cy, r) {
    return `M${cx} ${cy + r * 0.9} C${cx - r * 1.9} ${cy - r * 0.2} ${cx - r * 0.9} ${cy - r * 1.6} ${cx} ${cy - r * 0.5}` +
      ` C${cx + r * 0.9} ${cy - r * 1.6} ${cx + r * 1.9} ${cy - r * 0.2} ${cx} ${cy + r * 0.9}Z`;
  }
  function aster(mood, size) {
    const L = 94, T = 23.5, O = 7;
    const arms = (cls, grow) => s("g", { class: cls }, [30, 90, 150].map((a) =>
      s("rect", { x: 50 - (L + grow) / 2, y: 50 - (T + grow) / 2, width: L + grow, height: T + grow, rx: (T + grow) / 2, transform: `rotate(${a} 50 50)` })));
    const eyes = s("g", { class: "eyes" });
    for (const x of [42.65, 57.35]) {
      if (mood === "smitten") eyes.append(s("path", { class: "heart", d: heartPath(x, 46, 5) }));
      else {
        eyes.append(s("ellipse", { class: "fill", cx: x, cy: 46, rx: 3.1, ry: 4.4 }));
        eyes.append(s("circle", { class: "shine", cx: x + 1.1, cy: 44, r: 1.1 }));
      }
    }
    const hot = mood === "smitten";
    const mouth = hot
      ? s("path", { class: "fill", d: "M43 55 L57 55 Q56.4 63.5 50 63.5 Q43.6 63.5 43 55Z" })
      : s("path", { class: "stroke", d: "M44 55.2 Q50 61.2 56 55.2" });
    return s("svg", { class: "aster " + mood, viewBox: "-6 -6 112 112", width: size, height: size, "aria-hidden": "true", focusable: "false" },
      s("g", { class: "body" },
        s("g", { class: "arms" }, arms("outline", O), arms("petal", 0)),
        s("g", { class: "face" }, eyes,
          s("circle", { class: "cheek", cx: hot ? 35.5 : 36, cy: 54.5, r: hot ? 3.75 : 2.5 }),
          s("circle", { class: "cheek", cx: hot ? 64.5 : 64, cy: 54.5, r: hot ? 3.75 : 2.5 }),
          mouth)));
  }
  document.querySelectorAll("[data-aster]").forEach((el) => el.replaceWith(aster(el.dataset.aster, el.dataset.size || 40)));

  // The ticket follows passport.pdf: whichever leg of the trip is in the middle of the screen sets its name,
  // where it is, and who can read it there.
  const ticket = document.querySelector(".ticket");
  const nameEl = document.querySelector("[data-ticket-name]");
  const whereEl = document.querySelector("[data-ticket-where]");
  const serverEl = document.querySelector('[data-reader="server"]');
  const legs = [...document.querySelectorAll(".leg")];
  const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;
  let current = -1, swap;
  function show(i) {
    if (i === current || !ticket) return;
    current = i;
    const leg = legs[i];
    ticket.className = "ticket at-" + i;
    serverEl.className = leg.dataset.server === "brief" ? "brief" : "no";
    whereEl.textContent = leg.dataset.where;
    const name = leg.dataset.name;
    clearTimeout(swap);
    if (calm) { nameEl.textContent = name; return; }
    nameEl.classList.add("scramble");
    swap = setTimeout(() => { nameEl.textContent = name; nameEl.classList.remove("scramble"); }, 260);
  }
  if ("IntersectionObserver" in window && legs.length) {
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) show(legs.indexOf(e.target));
    }, { rootMargin: "-45% 0px -45% 0px" });
    legs.forEach((l) => io.observe(l));
  }

  // Copy the setup commands without the prompts.
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const src = document.getElementById(btn.dataset.copy);
      const text = [...src.querySelectorAll("code")].map((c) => c.innerText).join("\n")
        .split("\n").map((l) => l.replace(/^\$ /, "").replace(/\s+#.*$/, "")).join("\n");
      const label = btn.querySelector("span");
      try { await navigator.clipboard.writeText(text); label.textContent = "Copied"; }
      catch (_) { label.textContent = "Select and copy"; }
      setTimeout(() => { label.textContent = "Copy"; }, 1800);
    });
  });
})();
