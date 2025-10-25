// Un solo script per TUTTE le pagine.
// - Applica lo sfondo corrente (immagine o "solid:#RRGGBB").
// - Se trova <select id="bgSelect">, lo popola e salva la scelta.

(function () {
  function applyBg(choice) {
    if (choice && choice.startsWith("solid:")) {
      const color = choice.slice(6);
      document.documentElement.style.setProperty("--bg-solid", color);
      document.documentElement.style.setProperty("--bg-url", "none");
      // allineiamo anche il colore di base
      document.documentElement.style.setProperty("--bg-deep", color);
    } else {
      const url = choice || "/static/img/sfondo.png";
      document.documentElement.style.setProperty("--bg-solid", "transparent");
      document.documentElement.style.setProperty("--bg-url", `url("${url}")`);
      document.documentElement.style.setProperty("--bg-deep", "#081a3a");
    }
  }

  async function init() {
    try {
      const r = await fetch("/bg/list", { cache: "no-store" });
      const js = await r.json();
      const files = Array.isArray(js.files) ? js.files : [];
      const labels = js.labels || {};
      const current = js.current || files[0] || "/static/img/sfondo.png";

      // Applica sempre, anche se la pagina non ha il select
      applyBg(current);

      // Se presente il picker, popolalo e sincronizza
      const sel = document.getElementById("bgSelect");
      if (sel) {
        const optsImgs = files
          .map((f, i) => {
            const lab = labels[f] || `Sfondo ${i + 1}`;
            return `<option value="${f}">${lab}</option>`;
          })
          .join("");

        const solids = [
          { value: "solid:#0b1226", label: "Blu scuro" },
          { value: "solid:#111827", label: "Grafite" },
          { value: "solid:#0f172a", label: "Slate" },
          { value: "solid:#0a0a0a", label: "Nero" },
        ];
        const optsSolids =
          `<optgroup label="Tinta unita">` +
          solids.map((s) => `<option value="${s.value}">${s.label}</option>`).join("") +
          `</optgroup>`;

        if (!sel.options.length) sel.innerHTML = optsImgs + optsSolids;

        // seleziona lo stato corrente (sia immagine che solid)
        sel.value = current;
        if (sel.value !== current) {
          // se non esiste l'opzione (es. nuovo solid), aggiungila al volo
          const opt = document.createElement("option");
          opt.value = current;
          opt.textContent = current.startsWith("solid:") ? "Tinta personalizzata" : current;
          sel.appendChild(opt);
          sel.value = current;
        }

        sel.addEventListener("change", async () => {
          const val = sel.value;
          applyBg(val);
          try {
            await fetch("/bg/set", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ file: val }),
            });
          } catch (_) {}
        });
      }
    } catch (_) {
      applyBg("/static/img/sfondo.png");
    }
  }

  if (document.readyState !== "loading") init();
  else document.addEventListener("DOMContentLoaded", init);
})();
