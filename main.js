/* PHP2Shell brief — renders volatile values from data/status.json.
   No dependencies, no build step. If the JSON cannot be loaded the page
   still renders; status-dependent blocks show an explicit unavailable
   state instead of silently disappearing. */
(function () {
  "use strict";

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  function each(selector, fn) {
    Array.prototype.forEach.call(document.querySelectorAll(selector), fn);
  }

  function formatStamp(value) {
    var parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) { return value; }
    return parsed.toISOString().slice(0, 10) + " " +
      parsed.toISOString().slice(11, 16) + " UTC";
  }

  function renderTimestamp(data) {
    each("[data-status-timestamp], [data-status-footer-timestamp]", function (stamp) {
      if (!data || !data.lastUpdated) {
        stamp.textContent = "status data not loaded";
        stamp.classList.add("is-unavailable");
        return;
      }
      stamp.classList.remove("is-unavailable");
      stamp.textContent = "as of " + formatStamp(data.lastUpdated);
    });
  }

  function renderSeverity(data) {
    var target = document.querySelector("[data-status-severity]");
    if (target) {
      if (!data) {
        target.textContent = "status unavailable";
        target.classList.add("is-unavailable");
      } else {
        clear(target);
        target.appendChild(el("span", "chip chip--alert", data.severity));
        target.appendChild(el("span", "chip", data.cvssVector + " " + data.cvss));
        target.appendChild(el("span", "chip", "PHP " + data.affectedFrom + " and later"));
      }
    }
    each("[data-status-severity-line]", function (line) {
      if (!data) {
        line.textContent = "severity unknown";
        line.classList.add("is-unavailable");
        return;
      }
      line.classList.remove("is-unavailable");
      line.textContent = data.severity + ", " + data.cvssVector + " " + data.cvss;
    });
  }

  function fixedList(data) {
    if (!data || !data.fixedVersions || !data.fixedVersions.length) { return null; }
    var versions = data.fixedVersions.map(function (row) { return row.version; });
    if (versions.length < 2) { return versions[0]; }
    return versions.slice(0, -1).join(", ") + " and " + versions[versions.length - 1];
  }

  function renderFixed(data) {
    var list = fixedList(data);
    each("[data-status-fixed], [data-status-fixed-inline]", function (node) {
      node.textContent = list || "the patched releases";
    });
  }

  function renderVersions(data) {
    var body = document.querySelector("[data-status-versions]");
    if (!body) { return; }
    clear(body);
    if (!data || !data.fixedVersions || !data.fixedVersions.length) {
      body.appendChild(el("p", "note", "Version table unavailable."));
      return;
    }
    var table = el("table", "table");
    var head = el("thead");
    var headRow = el("tr");
    ["Branch", "Fixed version", "Branch end of life"].forEach(function (label) {
      headRow.appendChild(el("th", null, label));
    });
    head.appendChild(headRow);
    table.appendChild(head);
    var bodyEl = el("tbody");
    data.fixedVersions.forEach(function (row) {
      var tr = el("tr");
      tr.appendChild(el("td", "mono", "PHP " + row.branch));
      tr.appendChild(el("td", "mono is-fixed", row.version));
      tr.appendChild(el("td", null, row.eol));
      bodyEl.appendChild(tr);
    });
    table.appendChild(bodyEl);
    var wrap = el("div", "table-wrap");
    wrap.appendChild(table);
    body.appendChild(wrap);
  }

  function renderCves(data) {
    var body = document.querySelector("[data-status-cves]");
    if (!body) { return; }
    clear(body);
    if (!data || !data.cves || !data.cves.length) {
      body.appendChild(el("p", "note", "CVE summaries unavailable."));
      return;
    }
    var list = el("ul", "cves");
    data.cves.forEach(function (item) {
      var entry = el("li", "cve");
      entry.appendChild(el("p", "card__id", item.id + " · " + item.ghsa));
      entry.appendChild(el("p", "cve__title", item.name));
      entry.appendChild(el("p", "cve__summary", item.summary));
      var link = el("a", "link", "advisory");
      link.href = "https://github.com/php/php-src/security/advisories/" + item.ghsa;
      link.rel = "noopener noreferrer";
      link.setAttribute("aria-label", "Advisory for " + item.id);
      entry.appendChild(link);
      list.appendChild(entry);
    });
    body.appendChild(list);
  }

  function renderTiles(data) {
    var body = document.querySelector("[data-status-tiles]");
    if (!body) { return; }
    clear(body);
    if (!data) {
      body.appendChild(el("p", "note", "Status tiles unavailable."));
      return;
    }
    var tiles = [
      {
        value: String(data.exploitation ? data.exploitation.events.length : 0),
        label: "Dated exploit reports",
        body: "Attempts confirmed in the wild. CISA had not observed exploitation when it published its alert.",
        alert: true
      },
      {
        value: String(data.offlineServices ? data.offlineServices.length : 0),
        label: "Services taken offline",
        body: "Public bodies and platforms that pulled their sites down as a precaution."
      },
      {
        value: String(data.advisories ? data.advisories.length : 0),
        label: "Official advisories",
        body: "Vendor, researcher and government advisories tracked on this page."
      },
      {
        value: data.ai ? data.ai.value : "Frontier AI",
        label: "How it was found",
        body: data.ai ? data.ai.detail : "",
        source: data.ai ? data.ai.source : null
      }
    ];
    tiles.forEach(function (tile) {
      var box = el("div", "tile");
      var value = el("p", "tile__value" + (tile.alert ? " tile__value--alert" : ""), tile.value);
      box.appendChild(value);
      box.appendChild(el("p", "tile__label", tile.label));
      if (tile.body) { box.appendChild(el("p", "tile__body", tile.body)); }
      if (tile.source) {
        var link = el("a", "link", "source");
        link.href = tile.source;
        link.rel = "noopener noreferrer";
        link.setAttribute("aria-label", "Source for " + tile.label);
        box.appendChild(link);
      }
      body.appendChild(box);
    });
  }

  function renderExploitation(data) {
    var body = document.querySelector("[data-status-exploitation]");
    if (!body) { return; }
    clear(body);
    if (!data || !data.exploitation) {
      body.appendChild(el("p", "note", "Exploitation status unavailable."));
      return;
    }
    body.appendChild(el("p", "lead", data.exploitation.summary));
    var list = el("ul", "timeline");
    data.exploitation.events.forEach(function (event) {
      var item = el("li");
      item.appendChild(el("span", "timeline__when mono", event.when));
      var text = el("span", "timeline__what", event.what);
      if (event.source) {
        var link = el("a", "link", "source");
        link.href = event.source;
        link.rel = "noopener noreferrer";
        link.setAttribute("aria-label", "Source for the " + event.when + " report");
        text.appendChild(document.createTextNode(" "));
        text.appendChild(link);
      }
      item.appendChild(text);
      list.appendChild(item);
    });
    body.appendChild(list);
  }

  function renderList(selector, items, renderItem) {
    var body = document.querySelector(selector);
    if (!body) { return; }
    clear(body);
    if (!items || !items.length) {
      body.appendChild(el("p", "note", "Nothing to report."));
      return;
    }
    var list = el("ul", "cards");
    items.forEach(function (item) {
      var card = el("li", "card");
      renderItem(card, item);
      list.appendChild(card);
    });
    body.appendChild(list);
  }

  function renderOffline(data) {
    renderList("[data-status-offline]", data && data.offlineServices, function (card, item) {
      card.appendChild(el("h3", "card__title", item.who));
      card.appendChild(el("p", "card__body", item.what));
      var link = el("a", "link", "source");
      link.href = item.source;
      link.rel = "noopener noreferrer";
      link.setAttribute("aria-label", "Source for " + item.who);
      card.appendChild(link);
    });
  }

  function renderAdvisories(data) {
    renderList("[data-status-advisories]", data && data.advisories, function (card, item) {
      card.appendChild(el("h3", "card__title", item.who));
      card.appendChild(el("p", "card__body", item.level));
      var link = el("a", "link", "open");
      link.href = item.url;
      link.rel = "noopener noreferrer";
      link.setAttribute("aria-label", "Open the " + item.who + " advisory");
      card.appendChild(link);
    });
  }

  function renderTimeline(data) {
    var body = document.querySelector("[data-status-timeline]");
    if (!body) { return; }
    clear(body);
    if (!data || !data.timeline) {
      body.appendChild(el("p", "note", "Timeline unavailable."));
      return;
    }
    var list = el("ol", "timeline timeline--full");
    data.timeline.forEach(function (event) {
      var item = el("li");
      item.appendChild(el("span", "timeline__when mono", event.when));
      item.appendChild(el("span", "timeline__what", event.what));
      list.appendChild(item);
    });
    body.appendChild(list);
  }

  function initNavHighlight() {
    var links = Array.prototype.slice.call(
      document.querySelectorAll(".nav__list a[href^='#']")
    );
    if (!links.length || !("IntersectionObserver" in window)) { return; }
    var byId = {};
    links.forEach(function (link) {
      byId[link.getAttribute("href").slice(1)] = link;
    });
    function setCurrent(id) {
      links.forEach(function (link) {
        if (link.getAttribute("href") === "#" + id) {
          link.setAttribute("aria-current", "true");
          if (link.scrollIntoView) {
            link.scrollIntoView({ block: "nearest", inline: "nearest" });
          }
        } else {
          link.removeAttribute("aria-current");
        }
      });
    }
    var observer = new IntersectionObserver(function (entries) {
      var visible = entries.filter(function (entry) { return entry.isIntersecting; });
      if (!visible.length) { return; }
      setCurrent(visible[0].target.id);
    }, { rootMargin: "-45% 0px -50% 0px", threshold: 0 });
    Object.keys(byId).forEach(function (id) {
      var section = document.getElementById(id);
      if (section) { observer.observe(section); }
    });
    var masthead = document.querySelector(".masthead");
    if (masthead) {
      var topObserver = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) { setCurrent("__none__"); }
        });
      }, { threshold: 0.6 });
      topObserver.observe(masthead);
    }
  }

  function initNavToggle() {
    var toggle = document.querySelector(".nav__toggle");
    var nav = document.querySelector(".nav");
    if (!toggle || !nav) { return; }
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("nav--open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  function copyText(target, text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return Promise.reject(new Error("clipboard API unavailable"));
  }

  function legacyCopy(text) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
    document.body.removeChild(area);
    return ok;
  }

  function initCopyButtons() {
    each("[data-copy]", function (target) {
      var wrapper = target.closest(".code-wrap") || target;
      wrapper.classList.add("is-copyable");
      target.setAttribute("tabindex", "0");
      target.setAttribute("role", "button");
      target.setAttribute("aria-label", "Copy the mitigation snippet to the clipboard");

      function announce(state) {
        wrapper.classList.remove("is-copied", "is-failed");
        if (state) { wrapper.classList.add(state); }
      }

      function copy() {
        var text = target.getAttribute("data-copy") || target.textContent.trim();
        copyText(target, text).then(function () {
          announce("is-copied");
          setTimeout(function () { announce(null); }, 1400);
        }).catch(function () {
          if (legacyCopy(text)) {
            announce("is-copied");
            setTimeout(function () { announce(null); }, 1400);
          } else {
            announce("is-failed");
            setTimeout(function () { announce(null); }, 2000);
          }
        });
      }

      target.addEventListener("click", copy);
      target.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " " || event.key === "Spacebar") {
          event.preventDefault();
          copy();
        }
      });
    });
  }

  window.renderStatus = function (data) {
    renderTimestamp(data);
    renderSeverity(data);
    renderFixed(data);
    renderVersions(data);
    renderCves(data);
    renderTiles(data);
    renderExploitation(data);
    renderOffline(data);
    renderAdvisories(data);
    renderTimeline(data);
    document.body.classList.add("is-loaded");
  };

  function start() {
    initNavHighlight();
    initNavToggle();
    initCopyButtons();
    fetch("data/status.json", { cache: "no-cache" })
      .then(function (response) {
        if (!response.ok) { throw new Error("HTTP " + response.status); }
        return response.json();
      })
      .then(window.renderStatus)
      .catch(function () { window.renderStatus(null); });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
