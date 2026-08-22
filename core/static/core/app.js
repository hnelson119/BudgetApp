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
})();
