(() => {
  const root = document.documentElement;
  const button = document.querySelector(".theme-toggle");
  const storageKey = "household-budget-theme";

  const storedTheme = window.localStorage.getItem(storageKey);
  if (storedTheme === "dark" || storedTheme === "light") {
    root.dataset.theme = storedTheme;
  }

  const updateButtonState = () => {
    button?.setAttribute("aria-pressed", String(root.dataset.theme === "light"));
  };

  updateButtonState();
  button?.addEventListener("click", () => {
    root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
    window.localStorage.setItem(storageKey, root.dataset.theme);
    updateButtonState();
  });

  const clearClientStorage = () => {
    for (const storage of [window.localStorage, window.sessionStorage]) {
      try {
        storage.clear();
      } catch {
        // A browser privacy mode may make a storage area inaccessible.
      }
    }
    if ("caches" in window) {
      void window.caches
        .keys()
        .then((keys) => Promise.all(keys.map((key) => window.caches.delete(key))))
        .catch(() => {});
    }
    if (typeof window.indexedDB?.databases === "function") {
      void window.indexedDB
        .databases()
        .then((databases) => {
          for (const database of databases) {
            if (database.name) window.indexedDB.deleteDatabase(database.name);
          }
        })
        .catch(() => {});
    }
  };

  const clearAuthenticatedDom = () => {
    const shell = document.createElement("main");
    shell.className = "auth-shell";
    const card = document.createElement("section");
    card.className = "auth-card";
    const heading = document.createElement("h1");
    heading.textContent = "Signing out";
    const message = document.createElement("p");
    message.textContent = "This browser has cleared the private workspace.";
    card.append(heading, message);
    shell.append(card);
    document.body.replaceChildren(shell);
  };

  document.querySelectorAll("form[data-terminate-session]").forEach((form) => {
    form.addEventListener("submit", () => {
      clearClientStorage();
      window.setTimeout(clearAuthenticatedDom, 0);
    });
  });

  const frequency = document.querySelector("#id_frequency");
  if (frequency instanceof HTMLSelectElement) {
    const conditionalFields = [
      "id_weekdays",
      "id_day_of_month",
      "id_weekday",
      "id_ordinal",
      "id_month_of_year",
    ];
    const visibleFields = {
      weekly: ["id_weekdays"],
      monthly_day: ["id_day_of_month"],
      monthly_nth_weekday: ["id_weekday", "id_ordinal"],
      monthly_last_weekday: ["id_weekday"],
      annual: ["id_day_of_month", "id_month_of_year"],
    };
    const updateScheduleFields = () => {
      const visible = new Set(visibleFields[frequency.value] || []);
      conditionalFields.forEach((id) => {
        const field = document.querySelector(`#${id}`);
        const wrapper = field?.closest(".form-field");
        if (!(field instanceof HTMLElement) || !(wrapper instanceof HTMLElement)) return;
        const shouldShow = visible.has(id);
        wrapper.hidden = !shouldShow;
        wrapper.querySelectorAll("input, select").forEach((input) => {
          input.disabled = !shouldShow;
        });
      });
    };
    frequency.addEventListener("change", updateScheduleFields);
    updateScheduleFields();
  }
})();
