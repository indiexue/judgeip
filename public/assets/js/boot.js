/* JudgeIP — 首帧之前必须就位的两件事：给 <html> 挂上 .has-js，定下这一次用浅色还是深色。
   窄屏折叠导航、遮罩按钮、主题按钮都挂在 :root.has-js 下——禁用 JS 的访客拿不到一个点了没反应的控件。
   这段必须是 <head> 里的同步脚本：放进 defer 的 app.js 会晚一帧，
   手机上导航先整条摊开、再收成菜单按钮，深色的访客还会先看到一屏白底再变暗。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。 */
(function () {
  var root = document.documentElement;
  root.classList.add('has-js');

  /* 主题：访客点过切换按钮就用他选的（localStorage 里的 ipcx-theme：light / dark），没选过就跟系统偏好走。
     读存储包在 try 里：隐私模式或禁用了站点数据时，碰一下 localStorage 就会抛异常，那时当作没选过。
     这里只管首帧；之后的切换、跟随系统变化、跨标签页同步都在 app.js，两边的判定必须一致。 */
  var stored = null;
  try { stored = window.localStorage.getItem('ipcx-theme'); } catch (e) { stored = null; }
  var dark = stored === 'dark' ||
    (stored !== 'light' && !!window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  root.setAttribute('data-theme', dark ? 'dark' : 'light');
  if (!dark) return;

  /* <meta name="color-scheme"> 与 <meta name="theme-color"> 在 HTML 里按浅色写（没有 JS 时就是浅色），
     深色的值放在各自的 data-dark 上——它们排在本脚本前面，此刻已经在文档里了 */
  var metas = document.querySelectorAll('meta[data-dark]');
  for (var i = 0; i < metas.length; i++) {
    metas[i].setAttribute('content', metas[i].getAttribute('data-dark'));
  }
})();
