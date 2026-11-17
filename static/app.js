// Tiny progressive enhancements. The app works without JavaScript.
document.addEventListener("submit", function (e) {
  var form = e.target;
  var msg = form.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) {
    e.preventDefault();
    return;
  }
  var btn = form.querySelector("button[data-busy]");
  if (btn) {
    // Disable after the submit event finishes so the form still posts.
    setTimeout(function () {
      btn.disabled = true;
      btn.textContent = btn.getAttribute("data-busy");
    }, 0);
  }
});

document.addEventListener("click", function (e) {
  if (e.target.closest("[data-print]")) {
    window.print();
  }
});

// Back/forward cache: re-enable a button that was disabled before navigating away.
window.addEventListener("pageshow", function () {
  document.querySelectorAll("button[data-busy]").forEach(function (b) {
    b.disabled = false;
    b.textContent = "Run lookup";
  });
});
