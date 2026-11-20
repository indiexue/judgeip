/* JudgeIP — Early first-paint theme & JS flag initializer */
(function () {
  var root = document.documentElement;
  root.classList.add('has-js');

  var stored = null;
  try {
    stored = window.localStorage.getItem('judgeip-theme') || window.localStorage.getItem('ipcx-theme');
  } catch (e) {
    stored = null;
  }
  var dark = stored === 'dark' ||
    (stored !== 'light' && !!window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  root.setAttribute('data-theme', dark ? 'dark' : 'light');
  if (!dark) return;

  var metas = document.querySelectorAll('meta[data-dark]');
  for (var i = 0; i < metas.length; i++) {
    metas[i].setAttribute('content', metas[i].getAttribute('data-dark'));
  }
})();
