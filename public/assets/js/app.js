/* JudgeIP — 全部脚本。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。 */
(function () {
  'use strict';

  /* 统一读最新 window.T，避免 SPA 切换中英文后仍用旧语言闭包 */
  var T = function (zh, en) {
    return window.T ? window.T(zh, en) : zh;
  };

  /* 复制当前 IP */
  document.addEventListener('click', function (event) {
    var button = event.target.closest('[data-copy-target]');
    if (!button) return;

    var source = document.getElementById(button.getAttribute('data-copy-target'));
    if (!source) return;

    /* 遮罩打开时页面上是 8.8.*.*，但复制要给真值——
       藏起来是为了不让旁边的人看见，不是为了让自己也拿不到。 */
    var text = (source.getAttribute('data-copy-value') || source.textContent).trim();
    var done = button.getAttribute('data-copy-done') || T('已复制', 'Copied');

    /* 按钮里还有一个图标，不能整段替换 textContent——只改文字那一节 */
    var label = button.querySelector('.copy__label') || button;
    var original = button.getAttribute('data-copy-label') || label.textContent;

    button.setAttribute('data-copy-label', original);

    var settle = function (message, tone) {
      label.textContent = message;
      button.classList.remove('is-done', 'is-fail');
      button.classList.add(tone);

      window.setTimeout(function () {
        label.textContent = original;
        button.classList.remove('is-done', 'is-fail');
      }, 2000);
    };

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () {
        settle(done, 'is-done');
      }, function () {
        settle(T('复制失败', 'Copy failed'), 'is-fail');
      });
      return;
    }

    /* 非安全上下文（本地 http 调试）下的退路 */
    var scratch = document.createElement('textarea');
    scratch.value = text;
    scratch.setAttribute('readonly', '');
    scratch.style.position = 'fixed';
    scratch.style.opacity = '0';
    document.body.appendChild(scratch);
    scratch.select();
    try {
      document.execCommand('copy');
      settle(done, 'is-done');
    } catch (e) {
      settle(T('复制失败', 'Copy failed'), 'is-fail');
    }
    document.body.removeChild(scratch);
  });

  /* 遮罩当前 IP：录屏、截图、投屏时把地址与主机名藏掉，再点一下还原。
     纯显示层的开关，不落存储、不发请求——刷新即回到显示状态。 */
  var MASK_LABEL = { on: T('隐藏 IP 地址', 'Hide IP address'), off: T('显示 IP 地址', 'Show IP address') };

  /* IPv4 留前两段（8.8.8.8 → 8.8.*.*）；IPv6 留前两组，其余整体收成两个星号。
     留两段是为了还能看出运营商的大致归属，又不至于定位到具体一户。 */
  function maskIp(value) {
    if (value.indexOf(':') !== -1) {
      return value.split(':').slice(0, 2).join(':') + ':*:*';
    }

    var octets = value.split('.');
    return octets.length === 4 ? octets[0] + '.' + octets[1] + '.*.*' : '*.*.*.*';
  }

  document.addEventListener('click', function (event) {
    var button = event.target.closest('[data-mask-toggle]');
    if (!button) return;

    var card = button.closest('.current');
    var ip = card && card.querySelector('.current__ip');
    if (!ip) return;

    var masked = button.getAttribute('aria-pressed') !== 'true';

    if (masked) {
      /* 真值只在这里存一次：之后的还原都读它，不做反向推算 */
      ip.setAttribute('data-copy-value', ip.textContent.trim());
      ip.textContent = maskIp(ip.textContent.trim());
    } else {
      ip.textContent = ip.getAttribute('data-copy-value') || ip.textContent;
      ip.removeAttribute('data-copy-value');
    }

    var query = document.querySelector('[data-mask-query]');
    if (query) {
      query.type = masked ? 'password' : 'text';
      query.setAttribute('aria-label', masked
        ? T('要查询的 IP 地址（已隐藏）', 'IP address to look up (hidden)')
        : T('要查询的 IP 地址', 'IP address to look up'));
    }

    card.classList.toggle('is-masked', masked);
    button.setAttribute('aria-pressed', masked ? 'true' : 'false');
    button.setAttribute('aria-label', masked ? MASK_LABEL.off : MASK_LABEL.on);
    button.setAttribute('title', masked ? MASK_LABEL.off : MASK_LABEL.on);
  });

  /* 导航折叠的断点，与 app.css 里「窄屏折叠」那段 media query 保持一致（改一处必须两边一起改）。
     下面开合菜单、下拉组两段都只读这一条，「宽屏」一律写成它不成立，不另写一条 min-width：
     缩放或非整数的设备像素比会让视口宽度落在 1030 与 1031 之间，两条各写各的就会有一段谁都不认。 */
  var NAV_COLLAPSED = '(max-width: 1080px)';

  /* 窄屏导航的开合（使用事件委托，支持 SPA 切换语言重建顶栏后继续生效） */
  var initNavbarControls = function () {
    var navbar = document.querySelector('[data-navbar]');
    var navToggle = navbar && navbar.querySelector('[data-nav-toggle]');
    if (!navbar || !navToggle) return;

    var setNavOpen = function (open) {
      navbar.classList.toggle('is-open', open);
      navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      navToggle.setAttribute('aria-label', open ? T('关闭导航菜单', 'Close menu') : T('打开导航菜单', 'Open menu'));
    };

    if (!navToggle.hasAttribute('data-nav-bound')) {
      navToggle.setAttribute('data-nav-bound', '1');
      navToggle.addEventListener('click', function () {
        setNavOpen(!navbar.classList.contains('is-open'));
      });
    }

    if (!navbar.hasAttribute('data-nav-global-bound')) {
      navbar.setAttribute('data-nav-global-bound', '1');
      document.addEventListener('click', function (event) {
        var nb = document.querySelector('[data-navbar]');
        var nt = nb && nb.querySelector('[data-nav-toggle]');
        if (!nb || !nt || !nb.classList.contains('is-open')) return;
        if (nb.contains(event.target)) return;
        nb.classList.remove('is-open');
        nt.setAttribute('aria-expanded', 'false');
        nt.setAttribute('aria-label', T('打开导航菜单', 'Open menu'));
      });

      document.addEventListener('keydown', function (event) {
        var nb = document.querySelector('[data-navbar]');
        var nt = nb && nb.querySelector('[data-nav-toggle]');
        if (event.key !== 'Escape' || !nb || !nt || !nb.classList.contains('is-open')) return;
        nb.classList.remove('is-open');
        nt.setAttribute('aria-expanded', 'false');
        nt.setAttribute('aria-label', T('打开导航菜单', 'Open menu'));
        nt.focus();
      });

      navbar.addEventListener('focusout', function (event) {
        var nt = navbar.querySelector('[data-nav-toggle]');
        if (!nt || !navbar.classList.contains('is-open')) return;
        var next = event.relatedTarget;
        if (!next || navbar.contains(next)) return;
        navbar.classList.remove('is-open');
        nt.setAttribute('aria-expanded', 'false');
        nt.setAttribute('aria-label', T('打开导航菜单', 'Open menu'));
      });

      if (window.matchMedia) {
        var narrow = window.matchMedia(NAV_COLLAPSED);
        var onWide = function (query) {
          var nb = document.querySelector('[data-navbar]');
          var nt = nb && nb.querySelector('[data-nav-toggle]');
          if (!query.matches && nb && nt) {
            nb.classList.remove('is-open');
            nt.setAttribute('aria-expanded', 'false');
            nt.setAttribute('aria-label', T('打开导航菜单', 'Open menu'));
          }
        };
        if (narrow.addEventListener) narrow.addEventListener('change', onWide);
        else if (narrow.addListener) narrow.addListener(onWide);
      }
    }
  };
  initNavbarControls();

  /* 下拉组（宽屏） */
  var initNavGroups = function () {
    var groups = document.querySelectorAll('[data-nav-group]');
    if (!groups.length || !window.matchMedia) return;
    var hoverNone = window.matchMedia('(hover: none)');
    var collapsed = window.matchMedia(NAV_COLLAPSED);

    var setExpanded = function (toggle, open) {
      if (collapsed.matches) return;
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    };

    var syncCollapsed = function () {
      var curGroups = document.querySelectorAll('[data-nav-group]');
      Array.prototype.forEach.call(curGroups, function (group) {
        var t = group.querySelector('[data-nav-group-toggle]');
        if (!t) return;
        if (collapsed.matches) {
          t.removeAttribute('aria-haspopup');
          t.removeAttribute('aria-expanded');
          group.classList.remove('is-open');
        } else {
          var hovered = false;
          try { hovered = group.matches(':hover'); } catch (e) { hovered = false; }
          var shown = !group.classList.contains('is-dismissed') &&
            (group.classList.contains('is-open') || group.contains(document.activeElement) || hovered);
          t.setAttribute('aria-haspopup', 'true');
          t.setAttribute('aria-expanded', shown ? 'true' : 'false');
        }
      });
    };
    syncCollapsed();

    var closeGroups = function (except) {
      var curGroups = document.querySelectorAll('[data-nav-group]');
      for (var g = 0; g < curGroups.length; g++) {
        if (curGroups[g] === except) continue;
        curGroups[g].classList.remove('is-open');
        var t = curGroups[g].querySelector('[data-nav-group-toggle]');
        if (t) setExpanded(t, false);
      }
    };

    Array.prototype.forEach.call(groups, function (group) {
      if (group.hasAttribute('data-nav-group-bound')) return;
      group.setAttribute('data-nav-group-bound', '1');
      var toggle = group.querySelector('[data-nav-group-toggle]');
      if (!toggle) return;

      group.addEventListener('mouseenter', function () {
        setExpanded(toggle, true);
      });
      group.addEventListener('mouseleave', function () {
        group.classList.remove('is-dismissed');
        if (!group.classList.contains('is-open')) setExpanded(toggle, false);
      });
      group.addEventListener('focusin', function () {
        if (!group.classList.contains('is-dismissed')) setExpanded(toggle, true);
      });
      group.addEventListener('focusout', function (event) {
        if (group.contains(event.relatedTarget)) return;
        group.classList.remove('is-dismissed');
        setExpanded(toggle, false);
      });

      toggle.addEventListener('click', function (event) {
        if (!hoverNone.matches || collapsed.matches || group.classList.contains('is-open')) return;
        event.preventDefault();
        closeGroups(group);
        group.classList.add('is-open');
        setExpanded(toggle, true);
      });
    });

    if (!window.__judgeNavGroupGlobalBound) {
      window.__judgeNavGroupGlobalBound = true;
      if (collapsed.addEventListener) collapsed.addEventListener('change', syncCollapsed);
      else if (collapsed.addListener) collapsed.addListener(syncCollapsed);

      document.addEventListener('click', function (event) {
        if (event.target.closest && event.target.closest('[data-nav-group]')) return;
        closeGroups(null);
      });

      document.addEventListener('keydown', function (event) {
        if (event.key !== 'Escape') return;
        var open = document.activeElement && document.activeElement.closest
          ? document.activeElement.closest('[data-nav-group]') : null;
        closeGroups(null);

        var hovered = null;
        try { hovered = document.querySelector('[data-nav-group]:hover'); } catch (e) { hovered = null; }
        if (hovered && hovered !== open) hovered.classList.add('is-dismissed');

        if (!open) return;
        open.classList.add('is-dismissed');
        var t = open.querySelector('[data-nav-group-toggle]');
        if (t) {
          setExpanded(t, false);
          t.focus();
        }
      });
    }
  };
  initNavGroups();

  /* ---------------------------------------------------------------- 浅色 / 深色

     首帧用哪一套已经由 boot.js 定好（<html data-theme>），这里接手之后的事：
     - 导航条上的按钮点一下换到另一套，并把选择记进 localStorage（ipcx-theme：light / dark）。
       选的正好和系统偏好一样时不记，反而把记录删掉——等于回到「跟随系统」：
       否则随手点过一次，以后系统傍晚自动转深色，本站就再也不跟了；
     - 没有记录时跟着系统偏好实时变，不必刷新；
     - 另一个标签页里换了主题，这一页由 storage 事件同步；从 bfcache 回来的旧页面收不到那个事件，pageshow 时补一次。
     存储读写都包在 try 里：隐私模式下 localStorage 可能一碰就抛异常，那时只是记不住，切换本身照常。
     这一段与 boot.js 里的首帧判定是同一套规则，改一处必须两边一起改。 */
  (function () {
    var THEME_KEY = 'judgeip-theme';
    var root = document.documentElement;
    var prefersDark = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

    var themeLabel = function (theme) {
      return theme === 'dark' ? T('切换到浅色模式', 'Switch to light mode') : T('切换到深色模式', 'Switch to dark mode');
    };

    var systemTheme = function () {
      return prefersDark && prefersDark.matches ? 'dark' : 'light';
    };

    var storedTheme = function () {
      try {
        var value = window.localStorage.getItem(THEME_KEY);
        return value === 'dark' || value === 'light' ? value : null;
      } catch (e) {
        return null;
      }
    };

    var currentTheme = function () {
      return root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    };

    var syncButton = function (theme) {
      var button = document.querySelector('[data-theme-toggle]');
      if (!button) return;
      var label = themeLabel(theme);
      button.setAttribute('aria-label', label);
      button.setAttribute('title', label);
    };

    var applyTheme = function (theme) {
      if (theme !== currentTheme()) {
        root.classList.add('is-theme-switching');
        var release = function () { root.classList.remove('is-theme-switching'); };
        if (window.requestAnimationFrame) {
          window.requestAnimationFrame(function () { window.requestAnimationFrame(release); });
        } else {
          window.setTimeout(release, 50);
        }
      }

      root.setAttribute('data-theme', theme);
      var metas = document.querySelectorAll('meta[data-' + theme + ']');
      for (var i = 0; i < metas.length; i++) {
        metas[i].setAttribute('content', metas[i].getAttribute('data-' + theme));
      }
      syncButton(theme);
    };

    var resolveTheme = function () {
      applyTheme(storedTheme() || systemTheme());
    };

    syncButton(currentTheme());

    document.addEventListener('click', function (event) {
      var btn = event.target && event.target.closest ? event.target.closest('[data-theme-toggle]') : null;
      if (!btn) return;
      var next = currentTheme() === 'dark' ? 'light' : 'dark';
      try {
        if (next === systemTheme()) window.localStorage.removeItem(THEME_KEY);
        else window.localStorage.setItem(THEME_KEY, next);
      } catch (e) { /* 存不了就只在这一页生效 */ }
      applyTheme(next);
    });

    document.addEventListener('keydown', function (event) {
      var btn = event.target && event.target.closest ? event.target.closest('[data-theme-toggle]') : null;
      if (btn && event.repeat && event.key === 'Enter') event.preventDefault();
    });

    document.addEventListener('judgeip:after-swap', function () {
      syncButton(currentTheme());
    });

    if (prefersDark) {
      if (prefersDark.addEventListener) prefersDark.addEventListener('change', resolveTheme);
      else if (prefersDark.addListener) prefersDark.addListener(resolveTheme);
    }

    window.addEventListener('storage', function (event) {
      if (event.key === THEME_KEY || event.key === null) resolveTheme();
    });

    window.addEventListener('pageshow', function (event) {
      if (event.persisted) resolveTheme();
    });
  })();

  /* ---------------------------------------------------------------- 多库定位

     同一条 IP 在几家地理库里各自落在哪个国家、州/省、城市。行已经由服务端摆好，这里只往格子里填。

     查看自己的 IP 时（data-self="1"）：
     - 带 data-geo-url 的行由浏览器直接去问那家库（IP2Location / DB-IP / IPinfo），问的就是页面上这一条 IP：
       地址里明写着它，和服务端没配 key 时发出去的是同一条（GeoSources::url()）。免 key 接口的额度按调用方的 IP 计，
       请求从访客这边发，每个访客花的就是自己的那一份，而不是全站共用服务器出口的那几百次
       （那一份用完之后，每个新访客看到的都是「查询失败」）。IP 写在地址里，这次请求从哪个出口、哪个地址族出去
       都不影响答案——开着分流代理、双栈的访客一样问得成。对方回显的 IP 仍要核对：说的不是页面上这一条的回答一概不填；
     - Cloudflare 没有「查任意 IP」的公开接口，只有 /cdn-cgi/trace 会说「连到它的那个客户端」在哪个国家
       （不再对外给州与城市）。它说的是这次连接的来源地址，所以必须就是页面上这一条才填；
     - 没问成的行（被拦、跨域读不到、对方报错或额度用完），连同只能由服务端查的行（MaxMind），
       等浏览器这几家都有了结果，合成一次 /geo/api?ip=…&only=… 交给本站服务端（带缓存与限流）。一页至多这一次。
     手动查询别的 IP 时：全部由服务端查（/geo/api?ip=…），浏览器不联系任何一家库，Cloudflare 那一行无从查起。
     两种情况带的都是页面上这条 IP。它就是调用方自己的地址时服务端直接查，不需要会话；不是的时候
     （手动查询，或出口不止一个、这次请求换了来源地址）凭会话里的放行记录查，记录不在就是 403，那几行落定成「查询失败」。

     地址与字段名都从 data-* 读——它们和 CSP 放行的源出自同一份 PHP 常量（GeoSources）。
     每一条路都有时限，任何一行都不会停在「查询中…」。 */
  var initGeoSection = function () {
  var geo = document.querySelector('[data-geo]');
  if (geo && window.fetch) {
    var geoIp = geo.getAttribute('data-ip') || '';
    var geoSelf = geo.getAttribute('data-self') === '1';

    /* 国家各库统一给 ISO 两位代码（IPinfo 只有代码），这里换成国旗 + 访客语言的国名，
       五行因此写法一致、能并排对照；州/省与城市保留各库原样的写法。 */
    var regionNames = null;
    try {
      if (window.Intl && Intl.DisplayNames) regionNames = new Intl.DisplayNames([window.I18N ? I18N.locale : 'zh-CN'], { type: 'region' });
    } catch (e) { regionNames = null; }
    /* 与 probe.js 同一套：Intl 给 HK 的「中国香港特别行政区」太长、给 TW 的「台湾」与站内其余写法不一致 */
    var SHORT_NAMES = { CN: T('中国大陆', 'Mainland China'), HK: T('中国香港', 'Hong Kong'), MO: T('中国澳门', 'Macau'), TW: T('中国台湾', 'Taiwan') };

    var countryLabel = function (code) {
      if (!/^[A-Z]{2}$/.test(code || '')) return '';
      var flag = String.fromCodePoint
        ? String.fromCodePoint(0x1F1E6 + code.charCodeAt(0) - 65, 0x1F1E6 + code.charCodeAt(1) - 65) + ' '
        : '';
      var name = SHORT_NAMES[code] || code;
      if (!SHORT_NAMES[code]) {
        try { name = (regionNames && regionNames.of(code)) || code; } catch (e) { name = code; }
      }
      return flag + name;
    };

    /* place 为 {country, region, city}；为空时显示 note。tail 是跟在位置后面的一句压暗的补充。
       城邦类地址（新加坡、摩纳哥）常见州与城市同名，只留一个，免得「新加坡 / Singapore / Singapore」 */
    var fillGeo = function (key, place, note, tail) {
      var cell = geo.querySelector('[data-geo-source="' + key + '"] .row__value');
      if (!cell) return;

      var parts = [];
      if (place) {
        var country = countryLabel(place.country);
        var region = place.region || '';
        var city = place.city || '';
        if (country) parts.push(country);
        if (region) parts.push(region);
        if (city && city.toLowerCase() !== region.toLowerCase()) parts.push(city);
      }

      cell.textContent = '';
      if (!parts.length) {
        var empty = document.createElement('span');
        empty.className = 'geo__note';
        empty.textContent = place ? T('库中无位置数据', 'No location in this database') : note;
        cell.appendChild(empty);
        return;
      }

      for (var i = 0; i < parts.length; i++) {
        if (i > 0) {
          var sep = document.createElement('span');
          sep.className = 'geo__sep';
          sep.setAttribute('aria-hidden', 'true');
          sep.textContent = '/';
          cell.appendChild(sep);
        }
        var part = document.createElement('span');
        part.textContent = parts[i];
        cell.appendChild(part);
      }

      if (tail) {
        var extra = document.createElement('span');
        extra.className = 'geo__note geo__tail';
        extra.textContent = tail;
        cell.appendChild(extra);
      }
    };

    /* IPv6 的写法不唯一（前导零、:: 的位置），比较前展开成 8 组 4 位；::ffff:1.2.3.4 与 1.2.3.4 是同一条地址。
       服务端核对回显（GeoSources::echoes()）认得的写法更多（十六进制的 ::ffff:、带方括号的）；
       这里不认的只是不采信浏览器这一次的回答，那一行改由服务端去查 */
    var ipKey = function (value) {
      var ip = String(value || '').trim().toLowerCase();
      var mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(ip);
      if (mapped) return mapped[1];
      if (ip.indexOf(':') === -1) return ip;
      var halves = ip.split('::');
      var head = halves[0] ? halves[0].split(':') : [];
      var tail = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
      var fill = [];
      if (halves.length > 1) {
        for (var n = head.length + tail.length; n < 8; n++) fill.push('0');
      }
      return head.concat(fill, tail).map(function (g) { return ('0000' + g).slice(-4); }).join(':');
    };

    /* 浏览器直连拿到的字段与服务端走同一套规则（GeoSources::text() / place()），两边填出来的才是同一种写法：
       去掉首尾空白，「-」是 IP2Location 的「不可用」，名字限长 120 个字符（GeoSources::MAX_NAME；
       一个代理对算一个字符，不从中间截开）；国家只认 ISO 两位代码，ZZ 是占位 */
    var GEO_NAME = /^(?:[\uD800-\uDBFF][\uDC00-\uDFFF]|[\s\S]){1,120}/;
    var geoText = function (value) {
      if (typeof value !== 'string') return '';
      var text = value.trim();
      if (text === '-') return '';
      var kept = GEO_NAME.exec(text);
      return kept ? kept[0] : '';
    };

    var geoPlace = function (country, region, city) {
      var code = geoText(country).toUpperCase();
      return {
        country: /^[A-Z]{2}$/.test(code) && code !== 'ZZ' ? code : '',
        region: geoText(region),
        city: geoText(city)
      };
    };

    /* 限时取回正文：resolve({status, text})，失败 reject('timeout' | 'error')。
       被代理或扩展拦下时 fetch 可能既不成功也不失败，所以必须自己计时；
       计时覆盖到读完响应体为止（响应头到了、正文卡住一样算超时）。
       没有 AbortController 的旧浏览器由计时器收尾，迟到的结果丢弃。 */
    var geoFetch = function (url, options, limit) {
      return new Promise(function (resolve, reject) {
        var settled = false;
        var ctl = window.AbortController ? new AbortController() : null;
        var timer = window.setTimeout(function () {
          if (settled) return;
          settled = true;
          if (ctl) ctl.abort();
          reject('timeout');
        }, limit);
        var settle = function (done, value) {
          if (settled) return;
          settled = true;
          window.clearTimeout(timer);
          done(value);
        };

        if (ctl) options.signal = ctl.signal;
        fetch(url, options).then(function (response) {
          return response.text().then(function (text) {
            settle(resolve, { status: response.status, text: text });
          });
        }).catch(function () {
          settle(reject, 'error');
        });
      });
    };

    /* 发给第三方的请求：不带 Cookie、不带来源页、不走缓存，也不加任何自定义请求头（一加就触发跨域预检） */
    var thirdParty = function () {
      return { credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' };
    };

    var isSet = function (value) {
      return value !== undefined && value !== null;
    };

    /* 浏览器直连一家库：采信就 resolve(place)，其余一律 resolve(null)、交给服务端。
       这里不细分失败原因——页面上最后写什么，以服务端那一次的回答为准。
       字段与清洗和 GeoSources::parse() 是同一套，改一边要两边一起改：HTTP 200，没有 error / errorCode（DB-IP 超额时照样回 200）。
       回显这一条这里比服务端严：必须回显、而且就是被查的这一条——空对象、只有一句 message、没有回显、
       或是在说另一条地址的回答，都不采信。这里不采信没有代价，那一行多走一次 /geo/api 而已。 */
    var askProvider = function (row) {
      var names = (row.getAttribute('data-geo-fields') || '').split(' ');
      return geoFetch(row.getAttribute('data-geo-url'), thirdParty(), 5000).then(function (result) {
        var data = JSON.parse(result.text);
        if (result.status !== 200 || !data || typeof data !== 'object' || isSet(data.error) || isSet(data.errorCode)) return null;
        var seen = geoText(data[names[0]]);
        if (!seen || ipKey(seen) !== ipKey(geoIp)) return null;
        return geoPlace(data[names[1]], data[names[2]], data[names[3]]);
      }).catch(function () {
        return null;
      });
    };

    var reasonNote = function (reason) {
      if (reason === 'limited') return T('查询额度已用完', 'Lookup quota used up');
      if (reason === 'timeout') return T('查询超时', 'Lookup timed out');
      return T('查询失败', 'Lookup failed');
    };

    /* 向本站服务端要 keys 这几行。服务端最坏要等上游 4 秒超时，这里给 12 秒，过了就按超时落定。
       X-Requested-With 是给服务端认「这是本站页面上的脚本发的」用的（GeoApi::SCRIPT_HEADER，值是公开的）：
       不发 Sec-Fetch-Site 的旧浏览器里，服务端靠它把这一次请求和别的站点嵌的一张 <img> 分开。
       同源请求加自定义头不触发预检；它只加在这一个请求上，发给第三方的一个自定义头都不带（见 thirdParty）。 */
    var askServer = function (keys, query) {
      if (!keys.length) return;

      var failAll = function (note) {
        keys.forEach(function (key) { fillGeo(key, null, note); });
      };

      geoFetch('/geo/api' + query, {
        credentials: 'same-origin',
        headers: { Accept: 'application/json', 'X-Requested-With': 'ipcx' }
      }, 12000).then(function (result) {
        var data = null;
        try { data = JSON.parse(result.text); } catch (e) { data = null; }

        if (result.status === 429 || (data && data.error === 'rate_limited')) {
          failAll(T('查询过于频繁', 'Too many lookups'));
          return;
        }
        if (!data || !data.ok || !data.sources) {
          failAll(T('查询失败', 'Lookup failed'));
          return;
        }
        /* 请求里带着页面上这条 IP，回来的理应就是它；万一不是，那是另一条地址的位置，不能填到这条 IP 名下 */
        if (ipKey(data.ip) !== ipKey(geoIp)) {
          failAll(T('查询失败', 'Lookup failed'));
          return;
        }

        keys.forEach(function (key) {
          var item = data.sources[key];
          if (item && item.status === 'ok') fillGeo(key, item, '');
          else fillGeo(key, null, reasonNote(item && item.reason));
        });
      }).catch(function (kind) {
        failAll(kind === 'timeout' ? T('查询超时', 'Lookup timed out') : T('查询失败', 'Lookup failed'));
      });
    };

    var geoRows = geo.querySelectorAll('[data-geo-source]');
    var geoKeys = [];
    var needServer = {};
    var attempts = [];

    /* 一行的浏览器直连：成了就地填上，没成记下来等服务端 */
    var tryBrowser = function (row, key) {
      return askProvider(row).then(function (place) {
        if (place) fillGeo(key, place, '');
        else needServer[key] = true;
      }).catch(function () {
        needServer[key] = true;
      });
    };

    for (var geoRow = 0; geoRow < geoRows.length; geoRow++) {
      var geoKey = geoRows[geoRow].getAttribute('data-geo-source');
      if (geoKey === 'cloudflare') continue;
      geoKeys.push(geoKey);
      if (geoSelf && geoRows[geoRow].getAttribute('data-geo-url')) attempts.push(tryBrowser(geoRows[geoRow], geoKey));
      else needServer[geoKey] = true;
    }

    /* 问服务端时永远带着页面上这条 IP。出口不止一个的网络里——多出口的代理、把不同连接映射到不同公网地址的
       运营商 NAT——这一次请求的来源地址未必还是页面上那一条：不带 ip 的话服务端查的是另一条地址，
       额度花了，答案却不能用。带上之后，它就是调用方自己的地址时服务端直接查；不是的时候，
       首页渲染时已经把它记进了会话的放行名单，服务端凭那条记录照查 */
    var geoQuery = '?ip=' + encodeURIComponent(geoIp);

    if (!geoSelf) {
      askServer(geoKeys, geoQuery);
    } else {
      /* 等浏览器这几家都落定（各自最多 5 秒）再去问服务端，一次问完：看一页至多打一次 /geo/api，
         浏览器全问成了、又没有只能由服务端查的行时，一次都不打 */
      Promise.all(attempts).then(function () {
        var left = geoKeys.filter(function (key) { return needServer[key] === true; });
        askServer(left, geoQuery + '&only=' + left.join(','));
      });
    }

    var cfRow = geo.querySelector('[data-geo-source="cloudflare"]');
    if (cfRow && !(geoSelf && cfRow.getAttribute('data-geo-url'))) {
      fillGeo('cloudflare', null, T('仅支持查询本机 IP', 'Only your own IP can be looked up'));
    } else if (cfRow) {
      geoFetch(cfRow.getAttribute('data-geo-url'), thirdParty(), 6000).then(function (result) {
        var trace = {};
        result.text.split('\n').forEach(function (line) {
          var at = line.indexOf('=');
          if (at > 0) trace[line.slice(0, at).trim()] = line.slice(at + 1).trim();
        });

        if (result.status !== 200 || !trace.ip) {
          fillGeo('cloudflare', null, T('查询失败', 'Lookup failed'));
        } else if (ipKey(trace.ip) !== ipKey(geoIp)) {
          fillGeo('cloudflare', null, T('出口 IP 不一致，无法对照', 'Exit IP differs, cannot compare'));
        } else {
          /* loc 查不到时是 XX，Tor 出口是 T1：都不是国家 */
          var loc = geoPlace(trace.loc === 'XX' ? '' : trace.loc, '', '');
          if (loc.country) fillGeo('cloudflare', loc, '', T('仅提供国家', 'Country only'));
          else fillGeo('cloudflare', null, T('未给出国家', 'No country given'));
        }
      }).catch(function (kind) {
        fillGeo('cloudflare', null, kind === 'timeout' ? T('查询超时', 'Lookup timed out') : T('查询失败', 'Lookup failed'));
      });
    }
  }
  };
  initGeoSection();

  /* ---------------------------------------------------------------- 查询与人机验证

     Turnstile 是隐藏式的（appearance: interaction-only）：点「查询」才在后台跑一次，
     通过就把 token 填进表单直接提交，访客全程看不到任何验证组件；
     只有 Cloudflare 判定这次需要人手点一下时，才把组件所在的那块就地变成对话框弹出来。

     几处取舍：
     - 页面加载后先以 execution: 'execute' 渲染好组件、不跑验证：iframe 提前就位，
       点下查询时省掉一次加载；访客根本不查询时也不会白白消耗一次验证。
     - 第二次及以后的验证一律「移除旧组件、重新渲染」，不用 turnstile.reset()：
       interaction-only 模式下 reset 之后若需要人工交互，组件可能一直保持隐藏，访客只会看到按钮卡在「验证中」。
     - retry: 'never'：失败就明确告诉访客、把按钮还给他，而不是在看不见的地方静默重试。
     - 免验证窗口内（服务端没有输出 [data-verify]）走普通提交，一行验证代码都不跑。 */
  var form = document.querySelector('.query');
  var submit = form && form.querySelector('.query__submit');

  var setBusy = function (label) {
    if (!submit) return;
    submit.disabled = true;
    submit.textContent = label;
  };

  var setIdle = function () {
    if (!submit) return;
    submit.disabled = false;
    submit.textContent = T('查询', 'Look up');
  };

  var gate = document.querySelector('[data-verify]');
  var tokenField = form && form.querySelector('[data-verify-token]');
  var verify = null;

  if (form && gate && tokenField) {
    verify = (function () {
      var box = gate.querySelector('[data-verify-widget]');
      var dialog = gate.querySelector('.verify__dialog');
      var sitekey = gate.getAttribute('data-sitekey') || '';
      var apiTag = document.querySelector('script[data-turnstile-api]');

      var widgetId = null;
      var fresh = false;      // 已渲染、尚未 execute 过：下一次验证可以直接用它
      var freshTheme = '';    // 那个组件是按哪套主题画的：访客之后换了主题，它就不能再直接用（见 start）
      var pending = false;    // 一次验证正在进行中
      var attempt = 0;        // 第几次验证：api.js 迟到时，排队的旧回调据此认出自己已经作废
      var watchdog = 0;
      var lastFocus = null;

      /* api.js 是 async 加载的，可能早于也可能晚于本脚本执行完。
         脚本的执行与 load 事件落在同一个任务里：此刻 window.turnstile 还不存在，
         就说明 load 事件一定还没派发，这时再挂监听不会漏掉。 */
      var apiState = window.turnstile ? 'ready' : 'loading';
      var apiWaiters = [];

      var settleApi = function (state) {
        apiState = state;
        var waiters = apiWaiters;
        apiWaiters = [];
        for (var i = 0; i < waiters.length; i++) waiters[i]();
      };

      if (apiState === 'loading') {
        if (!apiTag) {
          apiState = 'failed';
        } else {
          /* 迟到的 load 照样算数：之前那次验证已按超时处理，但下一次点击可以直接用上 */
          apiTag.addEventListener('load', function () { settleApi(window.turnstile ? 'ready' : 'failed'); });
          apiTag.addEventListener('error', function () { settleApi('failed'); });
        }
      }

      var withApi = function (callback) {
        if (apiState === 'loading') apiWaiters.push(callback);
        else callback();
      };

      /* ---- 错误提示：与服务端渲染的 .notice 同一个样子，只保留一条 ---- */
      var showError = function (message) {
        var old = form.querySelector('[data-verify-error]');
        if (old) old.parentNode.removeChild(old);
        if (!message) return;

        var note = document.createElement('p');
        note.className = 'notice';
        note.setAttribute('role', 'alert');
        note.setAttribute('data-verify-error', '');
        note.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true">'
          + '<circle cx="12" cy="12" r="9"></circle><path d="M12 7.5v5.2M12 16.3v.2"></path></svg><span></span>';
        note.querySelector('span').textContent = message;
        form.appendChild(note);
      };

      /* ---- 对话框：同一个节点就地切换样式，iframe 不移动、不重载 ---- */
      var openDialog = function () {
        if (!pending || gate.classList.contains('is-open')) return;
        lastFocus = document.activeElement;
        gate.classList.add('is-open');
        dialog.setAttribute('role', 'dialog');
        dialog.setAttribute('aria-modal', 'true');
        dialog.focus();
      };

      var closeDialog = function () {
        if (!gate.classList.contains('is-open')) return;
        gate.classList.remove('is-open');
        dialog.removeAttribute('role');
        dialog.removeAttribute('aria-modal');
        /* 点「查询」时按钮随即被禁用，焦点早已掉回 <body>；这种情况下交还给查询按钮，回车即可重试 */
        var back = lastFocus && lastFocus !== document.body && !lastFocus.disabled ? lastFocus : submit;
        if (back && back.focus) back.focus();
        lastFocus = null;
      };

      var clearWatchdog = function () {
        if (watchdog) window.clearTimeout(watchdog);
        watchdog = 0;
      };

      var teardown = function () {
        if (widgetId !== null && window.turnstile) {
          try { window.turnstile.remove(widgetId); } catch (e) { /* 组件已经不在了，忽略 */ }
        }
        widgetId = null;
        fresh = false;
        tokenField.value = '';
      };

      /* 结束一次验证并把按钮还给访客。message 为空表示是访客自己取消的，不提示。 */
      var fail = function (message) {
        clearWatchdog();
        pending = false;
        fresh = false;
        setIdle();          /* 先把按钮还回去，关对话框时焦点才落得上 */
        closeDialog();
        showError(message);
        /* 推迟一拍再移除：这里可能正处在该组件自己的回调里 */
        window.setTimeout(function () { if (!pending) teardown(); }, 0);
      };

      var onToken = function (token) {
        if (!pending) return;
        clearWatchdog();
        pending = false;
        tokenField.value = token;
        closeDialog();
        setBusy(T('查询中', 'Looking up'));
        /* 走原型上的 submit()：不再触发 submit 事件，也不怕表单里哪天多出一个 name="submit" 的控件 */
        HTMLFormElement.prototype.submit.call(form);
      };

      var render = function (execution) {
        freshTheme = document.documentElement.getAttribute('data-theme') || '';
        widgetId = window.turnstile.render(box, {
          sitekey: sitekey,
          appearance: 'interaction-only',
          execution: execution,
          /* 跟着渲染这一刻的主题走；之后访客再换主题，已经渲染好的组件不重画——
             预渲染好还没用过的那个，由 start() 对照 freshTheme 换掉 */
          theme: document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light',
          size: window.innerWidth < 360 ? 'compact' : 'normal',
          language: window.I18N && I18N.lang === 'en' ? 'en' : 'zh-cn',
          retry: 'never',
          'response-field': false,
          callback: onToken,
          'error-callback': function () {
            fail(T('人机验证未通过，请重新点击查询。', 'Verification failed. Click Look up again.'));
            return true;
          },
          'expired-callback': function () {
            tokenField.value = '';
            fresh = false;
          },
          'timeout-callback': function () {
            fail(T('验证超时，请重新点击查询。', 'Verification timed out. Click Look up again.'));
          },
          'unsupported-callback': function () {
            fail(T('当前浏览器不支持人机验证，请更换浏览器后再试。', 'This browser does not support the verification. Try another browser.'));
          },
          'before-interactive-callback': openDialog
        });
        fresh = execution === 'execute';
      };

      /* 预先渲染好、不执行 */
      var prepare = function () {
        withApi(function () {
          if (apiState !== 'ready' || widgetId !== null || pending) return;
          try { render('execute'); } catch (e) { widgetId = null; fresh = false; }
        });
      };

      var armWatchdog = function (delay, message) {
        clearWatchdog();
        watchdog = window.setTimeout(function () {
          /* 对话框开着时访客正在操作，超时交给 timeout-callback，这里不插手 */
          if (pending && !gate.classList.contains('is-open')) fail(message);
        }, delay);
      };

      var start = function () {
        var current = ++attempt;
        pending = true;
        showError('');
        setBusy(T('验证中', 'Verifying'));

        /* api.js 若在本脚本挂上监听之前就已加载失败（访客网络连不上 Cloudflare），
           load / error 都不会再来——没有这道兜底，按钮会永远停在「验证中」 */
        if (apiState === 'loading') {
          armWatchdog(12000, T('人机验证组件加载失败，请检查网络后刷新页面重试。', 'The verification widget failed to load. Check your network and reload the page.'));
        }

        withApi(function () {
          if (!pending || current !== attempt) return;
          if (apiState !== 'ready') {
            fail(T('人机验证组件加载失败，请检查网络后刷新页面重试。', 'The verification widget failed to load. Check your network and reload the page.'));
            return;
          }

          try {
            /* 预渲染之后访客换过主题：组件的配色在渲染那一刻就定死了，拿它直接 execute，
               深色的对话框里会弹出一块浅色的组件（反过来也一样）。对不上就不用它，走下面重新渲染的那一支 */
            if (widgetId !== null && fresh && freshTheme === (document.documentElement.getAttribute('data-theme') || '')) {
              fresh = false;
              window.turnstile.execute(box);
            } else {
              teardown();
              render('render');   /* 默认 execution：渲染即开始验证 */
            }
          } catch (e) {
            fail(T('人机验证启动失败，请刷新页面重试。', 'The verification failed to start. Reload the page and try again.'));
            return;
          }

          /* 兜底：后台验证迟迟没有结论（网络卡住之类）就把按钮还回去 */
          armWatchdog(30000, T('人机验证超时，请重新点击查询。', 'Verification timed out. Click Look up again.'));
        });
      };

      gate.addEventListener('click', function (event) {
        if (event.target.closest('[data-verify-cancel]') && pending) fail('');
      });

      document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape' && pending && gate.classList.contains('is-open')) fail('');
      });

      prepare();

      return {
        pending: function () { return pending; },
        start: start,
        /* bfcache 恢复：旧 token 已被消费，组件整个换新 */
        restore: function () {
          clearWatchdog();
          pending = false;
          closeDialog();
          teardown();
          showError('');
          prepare();
        }
      };
    })();
  }

  if (form) {
    form.addEventListener('submit', function (event) {
      var input = form.querySelector('.query__input');
      var empty = !input || input.value.trim() === '';

      /* 需要验证且还没有 token：拦下这次提交，先在后台验证。
         空输入不必验证——服务端在人机验证之前就会把它拦下，不该为一句「请输入 IP」出一次题。 */
      if (verify && tokenField.value === '' && !empty) {
        event.preventDefault();
        if (!verify.pending()) verify.start();
        return;
      }

      /* 提交后短暂禁用按钮，避免重复提交消耗查询额度 */
      window.setTimeout(function () { setBusy(T('查询中', 'Looking up')); }, 0);
    });
  }

  /* 浏览器「后退」会从 bfcache 恢复旧页面：按钮还停在「查询中」，
     表单里还留着已经被 siteverify 消费过的 token——不重置的话下一次查询必然失败。 */
  window.addEventListener('pageshow', function (event) {
    if (!event.persisted) return;
    if (verify) verify.restore();
    setIdle();
  });

  /* ---------------------------------------------------------------- 站点图标

     连通性、服务状态两页（与首页连通性卡片）的字标里叠着一枚 favicon.is 的图标（View::favicon），
     样式上它一直是透明的：确认加载成功才给字标挂上 is-iconed、换成图标；加载失败就把图摘掉，留下字标。
     哪一步没走到（本脚本没加载上、图片迟迟不回来），访客看到的都是字标，不会是一个破图。
     这些都以 boot.js 挂上了 .has-js 为前提：JS 整个被禁用时 CSS 分不出成败，按加载成功摆，失败只剩空白小方框
     （见 status.css / connectivity.css，页面文案也照此写明）。
     单独包一层函数：这一段和上面几段没有任何共享的变量，别和它们抢名字。 */
  (function () {
    var settle = function (img, loaded) {
      var mark = img.parentNode;
      if (!mark) return;
      if (loaded) mark.classList.add('is-iconed');
      else mark.removeChild(img);
    };

    /* load / error 不冒泡，但捕获阶段照样经过 document：一个监听接住页面上所有图标，懒加载的也算。
       load 就算成功，不再看 naturalWidth——没写尺寸的 SVG 图标加载完了也可能报 0（各浏览器不一致）。 */
    var onEvent = function (event) {
      var img = event.target;
      if (img && img.nodeName === 'IMG' && img.hasAttribute('data-favicon')) settle(img, event.type === 'load');
    };
    document.addEventListener('load', onEvent, true);
    document.addEventListener('error', onEvent, true);

    /* 本脚本是 defer 的，缓存里的图标可能早就加载完了，事件已经错过：补扫一遍。 */
    var scanFavicons = function () {
      var icons = document.querySelectorAll('img[data-favicon]');
      for (var i = 0; i < icons.length; i++) {
        if (icons[i].complete && icons[i].naturalWidth > 0) settle(icons[i], true);
      }
    };
    scanFavicons();
    document.addEventListener('judgeip:after-swap', function (event) {
      if (event.detail && event.detail.langChanged) {
        initNavbarControls();
        initNavGroups();
      }
      initGeoSection();
      scanFavicons();
    });
  })();
})();
