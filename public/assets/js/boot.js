/* JudgeIP — Early first-paint theme & JS flag initializer */
(function () {
  var root = document.documentElement;
  root.classList.add('has-js');

  /* 中英文：页面语言由服务端写进 <html lang>，各脚本用 T('中文', 'English') 取当前语言的文案，
     站内链接用 I18N.path('/ai') 补上 /en 前缀。boot.js 同步加载，其余脚本都晚于它执行 */
  var lang = String(root.getAttribute('lang') || '').toLowerCase().indexOf('en') === 0 ? 'en' : 'zh';
  window.I18N = {
    lang: lang,
    locale: lang === 'en' ? 'en' : 'zh-CN',
    t: function (zh, en) {
      return lang === 'en' && en !== undefined ? en : zh;
    },
    path: function (p) {
      if (lang !== 'en') return p;
      return p === '/' ? '/en' : '/en' + p;
    }
  };
  window.T = window.I18N.t;

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
