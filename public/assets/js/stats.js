/* JudgeIP — 站点统计条客户端刷新。
   页面加载后拉取 /api/stats 最新计数：SSR 已渲染时只更新数字；
   SSR 因暂时性故障未渲染时，若 API 恢复则补建统计条。
   拉取失败保持现状或继续隐藏，绝不展示虚构数字。 */
(function () {
  'use strict';

  var wrap = document.querySelector('[data-site-stats]');
  if (!wrap || !window.fetch) return;

  var T = window.T || function (zh) { return zh; };
  var fmt = function (n) { return Number(n).toLocaleString('en-US'); };

  function fill(stats) {
    var total = wrap.querySelector('[data-stats-total]');
    var today = wrap.querySelector('[data-stats-today]');
    var since = wrap.querySelector('[data-stats-since]');
    if (total) total.textContent = fmt(stats.totalChecks);
    if (today) today.textContent = fmt(stats.todayChecks);
    if (since && stats.onlineSince) since.textContent = stats.onlineSince;
  }

  function build(stats) {
    wrap.innerHTML =
      '<span class="site-stats__item">' +
        '<svg class="site-stats__icon" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M3 13V8h2v5H3zm4 0V3h2v10H7zm4 0V6h2v7h-2z"/></svg>' +
        T('已检测', 'Checked') + ' <strong class="mono" data-stats-total>' + fmt(stats.totalChecks) + '</strong> ' + T('次', 'times') +
      '</span>' +
      '<span class="site-stats__item site-stats__item--today">' +
        '<span class="site-stats__dot" aria-hidden="true"></span>' +
        T('今日', 'Today') + ' <strong class="mono" data-stats-today>' + fmt(stats.todayChecks) + '</strong> ' + T('次', 'times') +
      '</span>' +
      '<span class="site-stats__item">' +
        '<svg class="site-stats__icon" viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M13 2h-9a1 1 0 0 0-1 1v10a1 1 0 0 0 1-1V3a1 1 0 0 0-1-1zM5 4h6v2H5V4zm0 4h6v2H5V8z"/></svg>' +
        T('上线于', 'Online since') + ' <strong class="mono" data-stats-since>' + (stats.onlineSince || '') + '</strong>' +
      '</span>';
  }

  fetch('/api/stats', { headers: { Accept: 'application/json' } })
    .then(function (res) { return res.ok ? res.json() : null; })
    .then(function (data) {
      if (!data || !data.ok || typeof data.totalChecks !== 'number') return;
      if (wrap.hidden) {
        build(data);
        wrap.hidden = false;
      } else {
        fill(data);
      }
    })
    .catch(function () { /* 保持 SSR 现状或继续隐藏 */ });
})();
