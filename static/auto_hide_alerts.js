document.addEventListener('DOMContentLoaded', function () {
  var alerts = document.querySelectorAll('.alert');
  if (!alerts.length) return;

  setTimeout(function () {
    alerts.forEach(function (el) {
      el.classList.add('is-hiding');
      setTimeout(function () {
        if (el && el.parentNode) {
          el.parentNode.removeChild(el);
        }
      }, 450);
    });
  }, 3000);
});


