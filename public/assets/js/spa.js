/* JudgeIP — 全站 SPA 无刷新导航与智能预加载（类似 IPFinal 的瞬时切换体验）。
   保留顶栏与页脚，点击任意同源站内链接时原地替换 <main>、样式表与页级脚本，
   支持 hover/touchstart/focus 提前预加载与内存短期缓存、顶部细进度条、前进/后退与语言切换。 */
(function () {
  'use strict';

  if (!window.fetch || !window.DOMParser || !window.history || !window.history.pushState) return;

  /* 公共基础设施脚本：页面首次加载后长驻内存，切换页面时不需要重复执行 */
  var PERSISTENT_JS = {
    '/assets/js/boot.js': true,
    '/assets/js/app.js': true,
    '/assets/js/spa.js': true,
    '/assets/js/probe.js': true,
    '/assets/js/history.js': true,
    '/assets/vendor/fingerprintjs2.min.js': true,
    '/assets/vendor/fingerprintjs3.min.js': true
  };

  /* 不拦截的路径前缀或扩展名（API / 原始文件 / 卡片图像 / 终端接口等） */
  var SKIP_PATH = /^\/(?:api\/|card\.svg|mcp|sitemap\.xml|robots\.txt|favicon\.svg|logo\.svg|og\.png|assets\/|geo\/api|dnsleak\/api|cloudflare\/turnstile|ip-lookup|ip$|json$)/i;

  /* 内存 HTML 缓存（key = pathname + search）：短期复用已预加载或刚访问过的页面 */
  var CACHE_TTL_MS = 20000;
  var CACHE_MAX = 24;
  var htmlCache = new Map();
  var inflightPrefetch = new Map();
  var scriptTextCache = new Map();
  var activeNavController = null;
  var navGeneration = 0;

  /* ---------------------------------------------------------------- 顶部轻量进度条 */
  var bar = document.createElement('div');
  bar.className = 'spa-progress';
  bar.setAttribute('aria-hidden', 'true');
  var barTimer = 0;
  var barHideTimer = 0;

  function ensureBar() {
    if (!bar.parentNode && document.body) document.body.appendChild(bar);
  }

  function startProgress() {
    ensureBar();
    window.clearTimeout(barTimer);
    window.clearTimeout(barHideTimer);
    bar.classList.remove('is-done');
    bar.style.width = '0%';
    /* 如果 60ms 内就命中缓存换完页面，就不闪出进度条，给人真正“零等待”的瞬切感 */
    barTimer = window.setTimeout(function () {
      bar.classList.add('is-active');
      bar.style.width = '36%';
      barTimer = window.setTimeout(function () {
        if (bar.classList.contains('is-active')) bar.style.width = '78%';
      }, 260);
    }, 60);
  }

  function finishProgress() {
    window.clearTimeout(barTimer);
    if (!bar.classList.contains('is-active')) return;
    bar.style.width = '100%';
    bar.classList.add('is-done');
    barHideTimer = window.setTimeout(function () {
      bar.classList.remove('is-active', 'is-done');
      bar.style.width = '0%';
    }, 240);
  }

  /* ---------------------------------------------------------------- URL 判定与缓存 */
  function normalizeKey(urlObj) {
    return urlObj.pathname + urlObj.search;
  }

  /* 这些页面渲染时会向多个上游查询 IP，悬停预加载会白白消耗免费额度，只在点击时请求 */
  var LOOKUP_ROUTE = /^(?:\/en)?(?:\/(?:ip\/.*|platforms|card|native-ip|residential-ip|tiktok-ip)?)?\/?$/;

  function shouldInterceptLink(anchor) {
    if (!anchor || anchor.nodeName !== 'A') return false;
    if (anchor.hasAttribute('download') || anchor.hasAttribute('data-no-spa')) return false;
    var target = (anchor.getAttribute('target') || '').toLowerCase();
    if (target && target !== '_self') return false;
    var rawHref = anchor.getAttribute('href');
    if (!rawHref || rawHref.charAt(0) === '#') return false;
    if (/^(?:mailto:|tel:|javascript:|data:|blob:)/i.test(rawHref)) return false;

    var url;
    try {
      url = new URL(anchor.href, window.location.href);
    } catch (e) {
      return false;
    }
    if (url.origin !== window.location.origin) return false;
    if (SKIP_PATH.test(url.pathname)) return false;
    /* 纯同页 hash 跳转交给浏览器原生平滑滚动 */
    if (url.pathname === window.location.pathname && url.search === window.location.search && url.hash) {
      return false;
    }
    return true;
  }

  function getCached(key) {
    var entry = htmlCache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.at > CACHE_TTL_MS) {
      htmlCache.delete(key);
      return null;
    }
    return entry;
  }

  function setCached(key, html, finalUrl) {
    if (htmlCache.size >= CACHE_MAX) {
      var oldest = htmlCache.keys().next().value;
      if (oldest !== undefined) htmlCache.delete(oldest);
    }
    htmlCache.set(key, { html: html, finalUrl: finalUrl, at: Date.now() });
  }

  function fetchHtml(urlStr, signal) {
    return fetch(urlStr, {
      credentials: 'same-origin',
      headers: {
        'Accept': 'text/html,application/xhtml+xml',
        'X-JudgeIP-SPA': '1'
      },
      signal: signal
    }).then(function (res) {
      var ct = (res.headers.get('content-type') || '').toLowerCase();
      if (ct.indexOf('text/html') === -1) {
        throw { nonHtml: true, url: res.url || urlStr };
      }
      return res.text().then(function (html) {
        return { html: html, finalUrl: res.url || urlStr, ok: res.ok, status: res.status };
      });
    });
  }

  function prefetch(urlStr) {
    var urlObj;
    try {
      urlObj = new URL(urlStr, window.location.href);
    } catch (e) {
      return;
    }
    if (LOOKUP_ROUTE.test(urlObj.pathname)) return;
    var key = normalizeKey(urlObj);
    if (key === normalizeKey(window.location)) return;
    if (getCached(key) || inflightPrefetch.has(key)) return;

    var req = fetchHtml(urlObj.href)
      .then(function (res) {
        if (res.ok) setCached(key, res.html, res.finalUrl);
        return res;
      })
      .catch(function () { return null; })
      .finally(function () { inflightPrefetch.delete(key); });

    inflightPrefetch.set(key, req);
  }

  /* ---------------------------------------------------------------- 样式与脚本同步 */
  function syncStylesheets(nextDoc) {
    var currentLinks = Array.prototype.slice.call(document.head.querySelectorAll('link[rel="stylesheet"]'));
    var nextLinks = Array.prototype.slice.call(nextDoc.head.querySelectorAll('link[rel="stylesheet"]'));

    var nextSet = {};
    var toAdd = [];
    nextLinks.forEach(function (link) {
      var href = link.getAttribute('href');
      if (!href) return;
      nextSet[href] = true;
      if (!document.head.querySelector('link[rel="stylesheet"][href="' + href.replace(/"/g, '\\"') + '"]')) {
        toAdd.push(href);
      }
    });

    /* 加载新页特有 CSS，并等待其生效后再移除旧页特有 CSS（避免无样式闪烁） */
    var waitLoads = toAdd.map(function (href) {
      return new Promise(function (resolve) {
        var el = document.createElement('link');
        el.rel = 'stylesheet';
        el.href = href;
        var done = false;
        var finish = function () { if (!done) { done = true; resolve(); } };
        el.addEventListener('load', finish);
        el.addEventListener('error', finish);
        window.setTimeout(finish, 1200);
        document.head.appendChild(el);
      });
    });

    return Promise.all(waitLoads).then(function () {
      currentLinks.forEach(function (link) {
        var href = link.getAttribute('href');
        if (href && !nextSet[href]) {
          link.parentNode && link.parentNode.removeChild(link);
        }
      });
    });
  }

  function loadScriptOnce(src) {
    if (scriptTextCache.has(src)) return Promise.resolve(scriptTextCache.get(src));
    return fetch(src, { credentials: 'same-origin' })
      .then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.text();
      })
      .then(function (code) {
        scriptTextCache.set(src, code);
        return code;
      });
  }

  function runScriptTag(src) {
    return new Promise(function (resolve) {
      var s = document.createElement('script');
      s.src = src;
      s.async = false;
      var done = false;
      var finish = function () { if (!done) { done = true; resolve(); } };
      s.addEventListener('load', finish);
      s.addEventListener('error', finish);
      document.head.appendChild(s);
    });
  }

  function executePageScripts(nextDoc, gen) {
    var headScripts = Array.prototype.slice.call(nextDoc.head.querySelectorAll('script[src]'));
    var inlineMainScripts = Array.prototype.slice.call(nextDoc.querySelectorAll('main script'));

    /* 顺序执行新页面需要的外部脚本；基础设施脚本仅在尚未加载过时执行一次 */
    var chain = Promise.resolve();

    headScripts.forEach(function (tag) {
      var src = tag.getAttribute('src');
      if (!src) return;
      if (PERSISTENT_JS[src]) {
        /* 仅当当前文档还没加载过该基础脚本时补加载一次（例如从 / 跳到 /fingerprint 需要 vendor 脚本，或从 /tools 跳到 /split 需要 probe.js） */
        chain = chain.then(function () {
          if (gen !== navGeneration) return;
          if (document.head.querySelector('script[src="' + src.replace(/"/g, '\\"') + '"]')) return;
          return runScriptTag(src);
        });
        return;
      }

      /* 外部第三方脚本（如 Turnstile api.js）走标签注入 */
      if (/^https?:\/\//i.test(src)) {
        chain = chain.then(function () {
          if (gen !== navGeneration) return;
          if (document.head.querySelector('script[src="' + src.replace(/"/g, '\\"') + '"]')) return;
          return runScriptTag(src);
        });
        return;
      }

      /* 页级业务脚本（如 egress.js / platforms.js / ai.js / ip-search.js）：缓存源码并在新 DOM 下重新执行 */
      chain = chain.then(function () {
        if (gen !== navGeneration) return;
        return loadScriptOnce(src).then(function (code) {
          if (gen !== navGeneration) return;
          try {
            var fn = new Function(code);
            fn();
          } catch (err) {
            if (window.console && console.error) console.error('[JudgeIP SPA] script error:', src, err);
          }
        }).catch(function () {});
      });
    });

    /* 执行 <main> 里的内联脚本（如 /card 页面的 SVG/PNG 导出脚本） */
    inlineMainScripts.forEach(function (tag) {
      var type = (tag.getAttribute('type') || '').toLowerCase();
      if (type && type !== 'text/javascript' && type !== 'application/javascript') return;
      var code = tag.textContent || '';
      if (!code.trim()) return;
      chain = chain.then(function () {
        if (gen !== navGeneration) return;
        try {
          var fn = new Function(code);
          fn();
        } catch (err) {
          if (window.console && console.error) console.error('[JudgeIP SPA] inline script error:', err);
        }
      });
    });

    return chain;
  }

  /* ---------------------------------------------------------------- 同步语言 / 顶栏 / 页脚 / Head 元信息 */
  function syncLang(nextDoc) {
    var nextLangAttr = nextDoc.documentElement.getAttribute('lang') || 'zh-CN';
    var prevLangAttr = document.documentElement.getAttribute('lang') || 'zh-CN';
    document.documentElement.setAttribute('lang', nextLangAttr);
    var lang = String(nextLangAttr).toLowerCase().indexOf('en') === 0 ? 'en' : 'zh';
    if (window.I18N) {
      window.I18N.lang = lang;
      window.I18N.locale = lang === 'en' ? 'en' : 'zh-CN';
      window.I18N.t = function (zh, en) { return lang === 'en' && en !== undefined ? en : zh; };
      window.I18N.path = function (p) {
        if (lang !== 'en') return p;
        return p === '/' ? '/en' : '/en' + p;
      };
      window.T = window.I18N.t;
    }
    return prevLangAttr !== nextLangAttr;
  }

  function syncHeadMeta(nextDoc) {
    document.title = nextDoc.title || document.title;

    var selectors = [
      'meta[name="description"]',
      'link[rel="canonical"]',
      'meta[property="og:url"]',
      'meta[property="og:title"]',
      'meta[property="og:description"]'
    ];
    selectors.forEach(function (sel) {
      var cur = document.head.querySelector(sel);
      var nxt = nextDoc.head.querySelector(sel);
      if (cur && nxt) {
        var attr = cur.tagName === 'LINK' ? 'href' : 'content';
        cur.setAttribute(attr, nxt.getAttribute(attr) || '');
      }
    });
  }

  function syncNavbarAndFooter(nextDoc, langChanged) {
    var curHeader = document.querySelector('header[data-navbar]');
    var nxtHeader = nextDoc.querySelector('header[data-navbar]');

    if (curHeader && nxtHeader) {
      if (langChanged) {
        /* 切换中英文时更新顶栏和页脚文案，并重新通知 app.js 绑定菜单交互 */
        curHeader.innerHTML = nxtHeader.innerHTML;
        var curFoot = document.querySelector('footer.foot');
        var nxtFoot = nextDoc.querySelector('footer.foot');
        if (curFoot && nxtFoot) curFoot.innerHTML = nxtFoot.innerHTML;
      } else {
        /* 同语言切换：保留 header DOM 不重建，仅就地同步激活状态、移动端当前页标题与语言切换链接 */
        var curLabel = curHeader.querySelector('.navbar__current');
        var nxtLabel = nxtHeader.querySelector('.navbar__current');
        if (curLabel && nxtLabel) curLabel.textContent = nxtLabel.textContent;

        var curLangSwitch = curHeader.querySelector('.lang-switch');
        var nxtLangSwitch = nxtHeader.querySelector('.lang-switch');
        if (curLangSwitch && nxtLangSwitch) {
          curLangSwitch.setAttribute('href', nxtLangSwitch.getAttribute('href') || '/');
        }

        /* 同步顶栏所有菜单项与子菜单项的 is-active / aria-current 状态 */
        var activeHrefSet = {};
        var nxtActives = nxtHeader.querySelectorAll('.is-active');
        for (var i = 0; i < nxtActives.length; i++) {
          var h = nxtActives[i].getAttribute('href');
          if (h) activeHrefSet[h] = true;
        }
        var curItems = curHeader.querySelectorAll('.nav__item, .nav__subitem');
        for (var j = 0; j < curItems.length; j++) {
          var item = curItems[j];
          var href = item.getAttribute('href') || '';
          var isGroupToggle = item.hasAttribute('data-nav-group-toggle');
          var active = false;
          if (isGroupToggle) {
            /* 组标签看对应新 DOM 里同位置是否高亮 */
            var nxtMatch = nxtHeader.querySelector('[data-nav-group-toggle][href="' + href.replace(/"/g, '\\"') + '"]');
            active = !!(nxtMatch && nxtMatch.classList.contains('is-active'));
          } else {
            active = !!activeHrefSet[href];
          }
          item.classList.toggle('is-active', active);
          if (!isGroupToggle && item.classList.contains('nav__item')) {
            if (active) item.setAttribute('aria-current', 'page');
            else item.removeAttribute('aria-current');
          }
        }
      }

      /* 切换页面时立刻收起移动端折叠菜单和桌面端下拉浮层 */
      curHeader.classList.remove('is-open');
      var navToggle = curHeader.querySelector('[data-nav-toggle]');
      if (navToggle) navToggle.setAttribute('aria-expanded', 'false');
      var groups = curHeader.querySelectorAll('[data-nav-group]');
      for (var g = 0; g < groups.length; g++) {
        groups[g].classList.remove('is-open');
        groups[g].classList.add('is-dismissed');
        var gt = groups[g].querySelector('[data-nav-group-toggle]');
        if (gt && gt.hasAttribute('aria-expanded')) gt.setAttribute('aria-expanded', 'false');
      }
      /* 鼠标移开或下一帧后允许下拉浮层再次响应 hover */
      window.setTimeout(function () {
        var gs = document.querySelectorAll('[data-nav-group].is-dismissed');
        for (var k = 0; k < gs.length; k++) gs[k].classList.remove('is-dismissed');
      }, 260);
    }
  }

  /* ---------------------------------------------------------------- 主导航函数 */
  function navigate(urlStr, opts) {
    opts = opts || {};
    var targetUrl;
    try {
      targetUrl = new URL(urlStr, window.location.href);
    } catch (e) {
      window.location.href = urlStr;
      return;
    }

    var key = normalizeKey(targetUrl);
    var gen = ++navGeneration;

    if (activeNavController) {
      try { activeNavController.abort(); } catch (e) {}
      activeNavController = null;
    }

    startProgress();

    /* 立即给用户“点击已响应”的顶栏视觉反馈 */
    var clickedNav = document.querySelector('header[data-navbar] a[href="' + key.replace(/"/g, '\\"') + '"]');
    if (clickedNav && clickedNav.classList.contains('nav__item') && !clickedNav.hasAttribute('data-nav-group-toggle')) {
      var prevActives = document.querySelectorAll('header[data-navbar] .nav__item.is-active');
      for (var p = 0; p < prevActives.length; p++) prevActives[p].classList.remove('is-active');
      clickedNav.classList.add('is-active');
    }

    var cached = !opts.noCache ? getCached(key) : null;
    var pending = !cached && !opts.noCache ? inflightPrefetch.get(key) : null;
    var htmlPromise;

    if (cached) {
      htmlPromise = Promise.resolve({ html: cached.html, finalUrl: cached.finalUrl, ok: true });
    } else if (pending) {
      htmlPromise = pending.then(function (res) {
        if (res && res.html) return res;
        var ctl = window.AbortController ? new AbortController() : null;
        activeNavController = ctl;
        return fetchHtml(targetUrl.href, ctl ? ctl.signal : undefined);
      });
    } else {
      var ctl = window.AbortController ? new AbortController() : null;
      activeNavController = ctl;
      htmlPromise = fetchHtml(targetUrl.href, ctl ? ctl.signal : undefined);
    }

    htmlPromise.then(function (res) {
      if (gen !== navGeneration) return;
      if (res.ok) setCached(key, res.html, res.finalUrl);

      var parser = new DOMParser();
      var nextDoc = parser.parseFromString(res.html, 'text/html');
      var nextWrap = nextDoc.querySelector('body > .wrap');
      var curWrap = document.querySelector('body > .wrap');

      if (!nextWrap || !curWrap) {
        window.location.href = targetUrl.href;
        return;
      }

      /* 触发离页事件，供运行中的计时器 / 探针 / Observer 清理 */
      document.dispatchEvent(new CustomEvent('judgeip:before-swap', { detail: { url: targetUrl.href } }));

      return syncStylesheets(nextDoc).then(function () {
        if (gen !== navGeneration) return;

        var langChanged = syncLang(nextDoc);
        syncHeadMeta(nextDoc);

        /* 更新 body class 与主体容器 */
        document.body.className = nextDoc.body.className || '';
        curWrap.className = nextWrap.className;
        curWrap.innerHTML = nextWrap.innerHTML;

        /* 同步顶栏与页脚 */
        syncNavbarAndFooter(nextDoc, langChanged);

        /* 同步地址栏（支持服务端重定向后的最终地址） */
        var finalObj;
        try { finalObj = new URL(res.finalUrl || targetUrl.href, window.location.href); } catch (e) { finalObj = targetUrl; }
        var pushTarget = finalObj.pathname + finalObj.search + (targetUrl.hash || '');
        if (!opts.skipHistory) {
          if (opts.replace) window.history.replaceState({ spa: true, url: pushTarget }, '', pushTarget);
          else window.history.pushState({ spa: true, url: pushTarget }, '', pushTarget);
        }

        /* 滚动到顶部或锚点 */
        if (targetUrl.hash) {
          var anchorEl = document.getElementById(targetUrl.hash.slice(1));
          if (anchorEl && anchorEl.scrollIntoView) anchorEl.scrollIntoView();
          else window.scrollTo(0, 0);
        } else {
          window.scrollTo(0, 0);
        }

        /* 极轻量入场过渡（纯 opacity，不阻塞点击） */
        var mainEl = document.getElementById('main');
        if (mainEl) {
          mainEl.classList.remove('is-spa-enter');
          void mainEl.offsetWidth;
          mainEl.classList.add('is-spa-enter');
        }

        finishProgress();

        /* 通知 app.js 重新初始化页内模块（多库定位、favicon 图标、表单、以及切语言后的顶栏事件） */
        document.dispatchEvent(new CustomEvent('judgeip:after-swap', {
          detail: { url: finalObj.href, langChanged: langChanged }
        }));

        /* 顺序执行目标页的客户端脚本 */
        return executePageScripts(nextDoc, gen);
      });
    }).catch(function (err) {
      if (gen !== navGeneration) return;
      if (err && err.name === 'AbortError') return;
      finishProgress();
      /* 降级为原生跳转，保证绝不白屏或卡死 */
      window.location.href = (err && err.url) || targetUrl.href;
    });
  }

  /* ---------------------------------------------------------------- 事件监听 */
  /* 拦截同源站内链接点击 */
  document.addEventListener('click', function (event) {
    if (event.defaultPrevented) return;
    if (event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;

    var anchor = event.target && event.target.closest ? event.target.closest('a[href]') : null;
    if (!shouldInterceptLink(anchor)) return;

    /* 如果点击的是当前完全相同的 URL（无 hash），滚动回顶部即可 */
    var dest;
    try { dest = new URL(anchor.href, window.location.href); } catch (e) { return; }
    if (dest.pathname === window.location.pathname && dest.search === window.location.search && !dest.hash) {
      event.preventDefault();
      window.scrollTo({ top: 0, behavior: 'smooth' });
      return;
    }

    event.preventDefault();
    navigate(dest.href);
  });

  /* 悬停 / 聚焦 / 触摸时提前预加载目标页 HTML，点击时直接从内存瞬切 */
  var prefetchTimer = 0;
  function schedulePrefetch(target, immediate) {
    var anchor = target && target.closest ? target.closest('a[href]') : null;
    if (!shouldInterceptLink(anchor)) return;
    var href = anchor.href;
    if (immediate) {
      prefetch(href);
      return;
    }
    window.clearTimeout(prefetchTimer);
    prefetchTimer = window.setTimeout(function () { prefetch(href); }, 45);
  }

  document.addEventListener('pointerover', function (event) {
    if (event.pointerType === 'touch') return;
    schedulePrefetch(event.target, false);
  }, { passive: true });

  document.addEventListener('pointerdown', function (event) {
    if (event.button === 0) schedulePrefetch(event.target, true);
  }, { passive: true });

  document.addEventListener('focusin', function (event) {
    schedulePrefetch(event.target, false);
  });

  /* 浏览器前进 / 后退 */
  window.addEventListener('popstate', function (event) {
    /* 首页 ip-search.js 的同页 IP 查询历史由 ip-search.js 自行处理（state.ip 存在且仍在首页） */
    if (event.state && event.state.ip !== undefined && document.getElementById('ip-hero')) {
      return;
    }
    navigate(window.location.href, { skipHistory: true });
  });

  /* 把当前首屏页面也顺手记进缓存，切换出去再点回首页时能瞬间恢复 */
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    window.history.replaceState(
      Object.assign({}, window.history.state || {}, { spa: true, url: window.location.pathname + window.location.search + window.location.hash }),
      ''
    );
  }

  /* 暴露轻量 API 供调试或站内脚本调用 */
  window.JudgeSpa = {
    navigate: navigate,
    prefetch: prefetch,
    clearCache: function () { htmlCache.clear(); }
  };
})();
