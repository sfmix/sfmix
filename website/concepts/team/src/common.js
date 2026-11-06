/* Shared helpers for the team-page concepts. Plain ES5-ish, no deps. */
(function () {
  var people = window.SFMIX_PEOPLE;
  var roleMeta = {};
  window.SFMIX_ROLES.forEach(function (r) { roleMeta[r.key] = r; });

  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function role(p, key) { for (var i = 0; i < p.roles.length; i++) if (p.roles[i].role === key) return p.roles[i]; return null; }
  function has(p, key) { return !!role(p, key); }
  function byRole(key) { return people.filter(function (p) { return has(p, key); }); }
  function byId(id) { for (var i = 0; i < people.length; i++) if (people[i].id === id) return people[i]; return null; }
  function initials(name) {
    var parts = name.replace(/[“”"].*?[“”"]/g, "").replace(/\./g, "").trim().split(/\s+/);
    return (parts[0][0] + (parts.length > 1 ? parts[parts.length - 1][0] : "")).toUpperCase();
  }
  function avatar(p, cls) {
    cls = "av " + (cls || "");
    if (p.photo) return '<img class="' + cls + '" src="' + p.photo + '" alt="" loading="lazy">';
    return '<span class="' + cls + ' av--initials" aria-hidden="true">' + initials(p.name) + "</span>";
  }
  /* The title shown under a name in a given context: officer title on the
     board, ops title in operations, otherwise the person's headline. */
  function titleFor(p, ctx) {
    var r = ctx && role(p, ctx);
    if (r && r.title) return r.title;
    return p.headline || "";
  }
  function chip(key, extra) {
    var m = roleMeta[key];
    return '<span class="chip chip--' + key + '">' + esc(m.label) + (extra ? " <span class=\"chip__x\">" + esc(extra) + "</span>" : "") + "</span>";
  }
  function chips(p, opts) {
    opts = opts || {};
    return '<span class="chips">' + p.roles.filter(function (r) { return !opts.except || opts.except.indexOf(r.role) === -1; })
      .map(function (r) { return chip(r.role, opts.titles && r.title ? r.title : (r.since && opts.since ? "since " + r.since : "")); }).join("") + "</span>";
  }
  function hasBio(p) { return p.bio && p.bio.length; }

  /* ---- Bio dialog ---- */
  var dlg;
  function ensureDialog() {
    if (dlg) return dlg;
    dlg = document.createElement("dialog");
    dlg.className = "bio-dialog";
    dlg.setAttribute("aria-labelledby", "bio-dialog-name");
    document.body.appendChild(dlg);
    dlg.addEventListener("click", function (e) { if (e.target === dlg) dlg.close(); });
    return dlg;
  }
  function openBio(id, opener) {
    var p = byId(id); if (!p) return;
    var d = ensureDialog();
    var titles = p.roles.filter(function (r) { return r.title; }).map(function (r) { return r.title; });
    d.innerHTML =
      '<button class="bio-dialog__close" type="button" aria-label="Close">&times;</button>' +
      '<div class="bio-dialog__head">' + avatar(p, "av--xl") +
      '<div><h2 id="bio-dialog-name">' + (p.url ? '<a href="' + p.url + '">' + esc(p.name) + "</a>" : esc(p.name)) + "</h2>" +
      (titles.length ? '<p class="bio-dialog__title">' + esc(titles.join(", ")) + "</p>" : "") +
      (p.affiliation ? '<p class="bio-dialog__aff">' + p.affiliation + "</p>" : "") +
      chips(p, { since: true }) + "</div></div>" +
      '<div class="bio-dialog__body">' +
      (hasBio(p) ? p.bio.map(function (para) { return "<p>" + para + "</p>"; }).join("") : '<p class="muted">Bio coming soon.</p>') +
      "</div>";
    d.querySelector(".bio-dialog__close").addEventListener("click", function () { d.close(); });
    d.addEventListener("close", function onClose() { d.removeEventListener("close", onClose); if (opener) opener.focus(); });
    d.showModal();
  }
  /* Any element with data-bio="<id>" opens that bio. */
  document.addEventListener("click", function (e) {
    var t = e.target.closest("[data-bio]");
    if (!t || e.target.closest("a[href]") && !e.target.closest("a[href]").hasAttribute("data-bio")) return;
    e.preventDefault();
    openBio(t.getAttribute("data-bio"), t);
  });

  window.Team = {
    people: people, roles: window.SFMIX_ROLES, roleMeta: roleMeta,
    esc: esc, role: role, has: has, byRole: byRole, byId: byId,
    avatar: avatar, chip: chip, chips: chips, titleFor: titleFor, hasBio: hasBio, openBio: openBio,
  };
})();
