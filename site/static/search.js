/* Documentation search.
   Progressive enhancement: the input does nothing until the index has loaded on
   first focus, and no page ever depends on it. */
(function () {
  "use strict";
  var box = document.getElementById("q");
  var out = document.getElementById("search-results");
  if (!box || !out) return;

  var base = document.documentElement.dataset.base || "/";
  var index = null;
  var pending = false;

  function load() {
    if (index || pending) return;
    pending = true;
    var lib = document.createElement("script");
    lib.src = base + "elasticlunr.min.js";
    lib.onload = function () {
      fetch(base + "search_index.en.json")
        .then(function (r) { return r.json(); })
        .then(function (data) {
          index = window.elasticlunr.Index.load(data);
          run();
        })
        .catch(function () { pending = false; });
    };
    lib.onerror = function () { pending = false; };
    document.head.appendChild(lib);
  }

  function run() {
    var q = box.value.trim();
    out.replaceChildren();
    if (!index || q.length < 2) return;

    index
      .search(q, {
        bool: "AND",
        expand: true,
        fields: { title: { boost: 3 }, description: { boost: 2 }, body: { boost: 1 } }
      })
      .slice(0, 8)
      .forEach(function (hit) {
        var doc = hit.doc || {};
        var li = document.createElement("li");
        var a = document.createElement("a");
        a.href = hit.ref;
        a.textContent = doc.title || hit.ref;
        var small = document.createElement("small");
        small.textContent = (doc.description || doc.body || "").slice(0, 110);
        a.appendChild(small);
        li.appendChild(a);
        out.appendChild(li);
      });
  }

  box.addEventListener("focus", load, { once: true });
  box.addEventListener("input", run);
  box.addEventListener("keydown", function (e) {
    if (e.key === "Escape") { box.value = ""; out.replaceChildren(); box.blur(); }
  });
})();
