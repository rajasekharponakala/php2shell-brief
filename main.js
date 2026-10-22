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

  function renderTimestamp(data) {
    var stamp = document.querySelector("[data-status-timestamp]");
    if (!stamp) { return; }
    if (!data || !data.lastUpdated) {
      stamp.textContent = "status unavailable";
      stamp.classList.add("is-unavailable");
      return;
    }
    var parsed = new Date(data.lastUpdated);
    var text = Number.isNaN(parsed.getTime())
      ? data.lastUpdated
      : parsed.toISOString().slice(0, 10) + " " +
        parsed.toISOString().slice(11, 16) + " UTC";
    stamp.textContent = "as of " + text;
  }

  function renderSeverity(data) {
    var target = document.querySelector("[data-status-severity]");
    if (!target) { return; }
    if (!data) {
      target.textContent = "status unavailable";
      target.classList.add("is-unavailable");
      return;
    }
    clear(target);
    target.appendChild(el("span", "chip chip--alert", data.severity));
    target.appendChild(el("span", "chip", data.cvssVector + " " + data.cvss));
    target.appendChild(el("span", "chip", "PHP " + data.affectedFrom + " and later"));
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
    body.appendChild(table);
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
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        var link = byId[entry.target.id];
        if (!link) { return; }
        if (entry.isIntersecting) {
          links.forEach(function (other) { other.removeAttribute("aria-current"); });
          link.setAttribute("aria-current", "true");
        }
      });
    }, { rootMargin: "-45% 0px -50% 0px", threshold: 0 });
    Object.keys(byId).forEach(function (id) {
      var section = document.getElementById(id);
      if (section) { observer.observe(section); }
    });
  }

  function initCopyButtons() {
    var targets = document.querySelectorAll("[data-copy]");
    Array.prototype.forEach.call(targets, function (target) {
      target.classList.add("is-copyable");
      target.setAttribute("tabindex", "0");
      target.setAttribute("role", "button");
      target.addEventListener("click", function () {
        var text = target.getAttribute("data-copy") || target.textContent.trim();
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            target.classList.add("is-copied");
            setTimeout(function () { target.classList.remove("is-copied"); }, 1400);
          });
        }
      });
    });
  }

  window.renderStatus = function (data) {
    renderTimestamp(data);
    renderSeverity(data);
    renderVersions(data);
    renderExploitation(data);
    renderOffline(data);
    renderAdvisories(data);
    renderTimeline(data);
    document.body.classList.add("is-loaded");
  };

  function start() {
    initNavHighlight();
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
