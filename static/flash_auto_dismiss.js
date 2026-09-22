(() => {
  "use strict";

  const AUTO_DISMISS_MS = 5000;
  const FADE_MS = 300;
  const SELECTOR = '[data-auto-dismiss="flash"]';

  function dismiss(element) {
    if (!element || element.dataset.autoDismissed === "1") {
      return;
    }

    element.dataset.autoDismissed = "1";
    element.style.transition = `opacity ${FADE_MS}ms ease`;
    element.style.opacity = "0";

    window.setTimeout(() => {
      element.remove();
    }, FADE_MS);
  }

  function schedule(root = document) {
    root.querySelectorAll(SELECTOR).forEach((element) => {
      if (element.dataset.autoDismissScheduled === "1") {
        return;
      }

      element.dataset.autoDismissScheduled = "1";
      window.setTimeout(() => dismiss(element), AUTO_DISMISS_MS);
    });
  }

  window.DhcpFlash = {
    dismiss,
    schedule,
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => schedule());
  } else {
    schedule();
  }
})();
