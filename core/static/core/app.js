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
