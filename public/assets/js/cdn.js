/* JudgeIP — CDN 命中节点。
   独立文件而非内联，是为了让 CSP 里不必出现 'unsafe-inline'。

   每家 CDN 的测试文件请求两次：第一次读节点头（含 DNS 解析与握手，耗时不算数），
   第二次在已经建好的连接上测延迟。清单、请求方法、要读哪些头都由 src/CdnProbes.php 渲染进 data-*，
   这里不再抄一份——页面上印着的「读 x-served-by」和脚本真正读的永远是同一个。

   跨站读响应头要对方在 Access-Control-Expose-Headers 里点名开放，多数 CDN 的测试文件没有核实过。
   所以三种落点都是正常结果，而不是错误：
     读到了        → 节点（城市 / 代码 / 节点 IP）
     连上但读不到   → 「可达 · 节点信息未开放」，只给延迟
     跨域被拒      → 用 no-cors 再测一次，分清「可达，但不允许跨域读取」与「不可达」
   任何一行都必须在限时内落定，绝不能停在「检测中」。

   「节点离你多远」要有访客的大致坐标，各家 CDN 都不给：向同源的 /geo/api?me=1 要本站对「它看到的你的地址」的
   位置记录，再拿 Cloudflare 那一行 trace 报的出口核对是不是同一个（见 settleVisitor）。
   这是本页唯一带自定义请求头的请求（见 loadMe），发给各家 CDN 的一个都不带。

   探测结果只留在当前页面里，不回传本站；问位置的那一次请求不带任何探测数据。 */
(function () {
  'use strict';

  var root = document.getElementById('cdn');
  if (!root) return;

  var P = window.IpcxProbe;

  var runButton = root.querySelector('[data-cdn-run]');
  var progress = root.querySelector('[data-cdn-progress]');
  var verdict = root.querySelector('[data-cdn-verdict]');
  var verdictTitle = root.querySelector('[data-cdn-verdict-title]');
  var verdictNote = root.querySelector('[data-cdn-verdict-note]');
  var chipsCell = root.querySelector('[data-cdn-chips]');
  var whereCell = root.querySelector('[data-cdn-where]');

  /* probe.js 没加载上（被拦、加载失败）或浏览器老到没有 fetch / Promise：说清楚再停下——
     一声不响地 return 的话，页面会一直写着「打开页面即自动开始」，十几行「待检测」永远不动。
     两种原因分开说：前者刷新一下多半就好，后者得换浏览器 */
  if (!P || !window.fetch || !window.Promise) {
    var broken = !P;
    if (verdict && verdictTitle && verdictNote) {
      verdict.className = 'verdict is-warn';
      verdict.hidden = false;
      verdictTitle.textContent = broken ? '检测脚本加载失败' : '当前浏览器无法运行检测';
      verdictNote.textContent = broken
        ? '本站的检测脚本（probe.js）没能加载：可能是网络中断，也可能被浏览器扩展拦截了。请刷新页面重试；仍然不行，检查是否有扩展拦截了本站脚本。'
        : '检测需要浏览器支持 fetch 与 Promise，当前浏览器太旧，请换用较新的浏览器。';
    }
    if (progress) progress.textContent = broken ? '检测脚本加载失败，请刷新页面重试。' : '当前浏览器不支持本页的检测。';
    if (runButton) runButton.disabled = true;
    return;
  }

  /* 并发数与时限由 src/CdnProbes.php 渲染进 data-*：页面上印的「每次请求最长等几秒、一家最多多久」
     就是从同一组常量算出来的。缺了属性才退回默认值 */
  function intAttr(name, fallback) {
    var n = parseInt(root.getAttribute(name) || '', 10);
    return n > 0 ? n : fallback;
  }

  var TIMEOUT = intAttr('data-timeout', 6000);
  var LANES = intAttr('data-lanes', 6);
  var BODY_TIMEOUT = intAttr('data-body-timeout', 4000);
  /* 单行兜底：一行最坏是「跨域请求 + 读正文 + 热连接再测一次」三段首尾相接（即页面上写的「一家最多约 N 秒」），
     各段自己都有时限；这一道再多留 4 秒，只防某个 Promise 永远不落定这类漏网的情况，正常路径碰不到 */
  var ROW_DEADLINE = 2 * TIMEOUT + BODY_TIMEOUT + 4000;
  /* 与连通性页同一套延迟分档 */
  var GOOD_MS = 100;
  var OK_MS = 250;
  /* 节点远近的分档不在这里：用 probe.js 的 P.distanceClass / P.DISTANCE_LABELS，与 /cloudflare、首页同一套 */
  /* 原始头值可能是一整串 via 链，节点格里只放这么长，完整值进 title */
  var LABEL_MAX = 40;

  /* 个别 CDN 用城市代码而不是机场代码；数据集里查不到时才查这张表 */
  var ALIASES = { WDC: 'IAD' };

  /* Bunny 的节点名形如 BunnyCDN-DE1-1052，中间一段的前两位多数是国家代码；
     但美国节点按州命名（NY、IL、LA……），不少州名和国家代码撞车（LA 老挝、IL 以色列、CO 哥伦比亚）。
     所以只认这张表：撞车的一概不收，宁可原样显示也不给错国旗。 */
  var BUNNY_CC = {
    DE: 'DE', FR: 'FR', NL: 'NL', UK: 'GB', GB: 'GB', ES: 'ES', IT: 'IT', SE: 'SE', PL: 'PL', CZ: 'CZ',
    AT: 'AT', CH: 'CH', DK: 'DK', FI: 'FI', NO: 'NO', PT: 'PT', RO: 'RO', HU: 'HU', BG: 'BG', GR: 'GR',
    IE: 'IE', BE: 'BE', SI: 'SI', HR: 'HR', RS: 'RS', UA: 'UA', TR: 'TR', AE: 'AE', ZA: 'ZA', NG: 'NG',
    JP: 'JP', KR: 'KR', SG: 'SG', HK: 'HK', TW: 'TW', AU: 'AU', NZ: 'NZ', TH: 'TH', MY: 'MY', PH: 'PH',
    VN: 'VN', BR: 'BR', CL: 'CL', MX: 'MX', PE: 'PE',
    NY: 'US', TX: 'US', FL: 'US', WA: 'US', NJ: 'US'
  };

  /* 网易对象存储背后的 CDN 厂商（cdn-source 的取值不公开，按常见缩写猜；认不出就原样显示） */
  var VENDORS = [
    [/^(ws|wangsu|chinanetcenter|wscdn)/i, '网宿'],
    [/^(ali|aliyun|alibaba|alicdn)/i, '阿里云'],
    [/^(tencent|qcloud|tx|txcdn)/i, '腾讯云'],
    [/^(baishan|bs)/i, '白山云'],
    [/^(ks|ksyun|kingsoft)/i, '金山云'],
    [/^(hw|huawei)/i, '华为云'],
    [/^(bd|baidu|bce)/i, '百度智能云'],
    [/^(dl|dilian)/i, '帝联'],
    [/^(volc|huoshan|bytedance|bytecdn)/i, '火山引擎'],
    [/^(qiniu|qn)/i, '七牛云'],
    [/^(upyun|upai)/i, '又拍云'],
    [/^(jd|jdcloud)/i, '京东云'],
    [/^(nos|netease|163|wy)/i, '网易自建']
  ];

  /* 城市即国家的地方：只知道国家，也就知道了城市。Bunny 的 HK1、字节的 hk… 借数据集里那座机场的坐标算距离——
     否则它们没有距离，和同一页上几家「香港 HKG」各标各的（别人标跨区接入，它标已识别） */
  var CITY_STATES = { HK: 'HKG', MO: 'MFM', SG: 'SIN' };

  var iataUrl = root.getAttribute('data-iata') || '';
  var meUrl = root.getAttribute('data-me') || '';

  var rows = Array.prototype.slice.call(root.querySelectorAll('[data-cdn]')).map(function (node) {
    var regions = null;
    try { regions = JSON.parse(node.getAttribute('data-regions') || 'null'); } catch (e) { regions = null; }
    return {
      node: node,
      key: node.getAttribute('data-cdn') || '',
      name: node.getAttribute('data-name') || '',
      url: node.getAttribute('data-url') || '',
      method: (node.getAttribute('data-method') || 'HEAD').toUpperCase(),
      parser: node.getAttribute('data-parser') || '',
      headers: (node.getAttribute('data-headers') || '').split(' ').filter(Boolean),
      regions: regions,
      cells: {
        node: node.querySelector('[data-cdn-node]'),
        ms: node.querySelector('[data-cdn-ms]'),
        state: node.querySelector('[data-cdn-state]')
      },
      result: null,
      parsed: null
    };
  }).filter(function (row) {
    return row.url && row.cells.node && row.cells.ms && row.cells.state;
  });

  if (!rows.length) return;

  /* 每次「重新检测」换一代；上一代还在路上的结果回来时直接丢掉，不覆盖新一轮 */
  var generation = 0;
  var running = false;
  var colos = {};
  /* 访客在哪，三样东西：
       me       本站对「它看到的你的地址」的位置记录；undefined 是还没回来，null 是没取到
       exit     Cloudflare 那一行 trace 报的出口 {ip, loc}；undefined 是还没回来，null 是没读到
       visitor  两者合出来、真正拿去判远近的那一份 {country, tier, lat, lon, region, city}（坐标可以是 null），null 是什么都不知道。
                country 是「你在哪」那一行显示的国家，tier 是分档用的国家，两者可以不同（见 settleVisitor）
     whereKind 记着是怎么合出来的，「距离按什么算」那一行据此措辞（见 settleVisitor / renderWhere） */
  var me;
  var exit;
  var visitor = null;
  var whereKind = 'loading';
  var nameIndex = null;
  var cityIndex = null;

  /* ---------------------------------------------------------------- 工具 */

  /* 结果格子里可能已经有上一轮的内容，整格换掉而不是往后追加 */
  function fill(cell, nodes) {
    cell.textContent = '';
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i]) cell.appendChild(nodes[i]);
    }
  }

  function dim(text) {
    return P.el('span', 'dim', text);
  }

  function trim(value) {
    return String(value === null || value === undefined ? '' : value).trim();
  }

  function shorten(text) {
    text = trim(text);
    return text.length > LABEL_MAX ? text.slice(0, LABEL_MAX - 1) + '…' : text;
  }

  /* 给 Promise 加一道时限：到点就以 fallback 落定，原来的 Promise 之后再回来也没人理 */
  function within(promise, ms, fallback) {
    return Promise.race([
      promise,
      P.sleep(ms).then(function () { return fallback; })
    ]);
  }

  /* 不需要的响应体也读完（几百字节）：HTTP/1.1 下没读完的连接没法复用，第二次就测不到热连接了 */
  function drain(response) {
    try {
      return within(response.arrayBuffer().then(function () { return null; }, function () { return null; }), BODY_TIMEOUT, null);
    } catch (e) {
      return Promise.resolve(null);
    }
  }

  function isIPv4(value) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
    if (!m) return false;
    for (var i = 1; i <= 4; i++) {
      if (Number(m[i]) > 255) return false;
    }
    return true;
  }

  function isIp(value) {
    value = trim(value);
    if (isIPv4(value)) return true;
    return value.indexOf(':') !== -1 && /^[0-9a-f:.]{2,45}$/i.test(value) && value.split(':').length >= 3;
  }

  /* 一段文本里的第一个 IP：IPv4 字面量、Akamai 式的 a23-45-67-89 主机名，或整段就是一个 IPv6 */
  function findIp(text) {
    text = trim(text);
    if (isIp(text)) return text;
    var m = /(^|[^\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])/.exec(text);
    if (m && isIPv4(m[2])) return m[2];
    m = /\ba(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})\b/.exec(text);
    if (m) {
      var ip = [m[1], m[2], m[3], m[4]].join('.');
      if (isIPv4(ip)) return ip;
    }
    return '';
  }

  /* 逗号分隔的多跳头（via、x-served-by）：响应每经过一层代理就往后追加一段，最后一段离你最近。
     不能直接 split(',')：字节的 via 形如 cache8.cn6720[0,0,200-0,H]，方括号里自己就带逗号；
     CDNetworks 的注释段 (Cdn Cache Server V2.0) 也可能带。只在括号外的逗号处断开。 */
  function hops(value) {
    var text = String(value || '');
    var out = [];
    var depth = 0;
    var start = 0;
    for (var i = 0; i < text.length; i++) {
      var c = text.charAt(i);
      if (c === '[' || c === '(') depth++;
      else if ((c === ']' || c === ')') && depth > 0) depth--;
      else if (c === ',' && depth === 0) {
        out.push(text.slice(start, i));
        start = i + 1;
      }
    }
    out.push(text.slice(start));
    return out.map(trim).filter(Boolean);
  }

  function lastEntry(value) {
    var parts = hops(value);
    return parts.length ? parts[parts.length - 1] : '';
  }

  /* 国家代码是否真的对应一个国家（Intl 认不出时会把代码原样还回来） */
  function realCountry(cc) {
    cc = String(cc || '').toUpperCase();
    if (!/^[A-Z]{2}$/.test(cc)) return '';
    var name = P.countryName(cc);
    return name && name !== cc ? name : '';
  }

  /* ---------------------------------------------------------------- 地点

     地点对象：{ code, city, cc, lat, lon, known }。
     known = 在数据集里查到了城市与坐标；只知道国家时 city 放国家名、known 为 false，不参与算距离。 */

  function iata(code) {
    var key = String(code || '').toUpperCase();
    var info = P.colo(colos, key);
    if (!info.known && ALIASES[key]) {
      var alias = P.colo(colos, ALIASES[key]);
      if (alias.known) {
        alias.code = key;
        return alias;
      }
    }
    return info;
  }

  /* 只接受数据集里查得到的代码：查不到就返回 null，由调用方原样显示，不当成城市 */
  function knownIata(code) {
    if (!/^[A-Za-z]{3}$/.test(code || '')) return null;
    var info = iata(code);
    return info.known ? info : null;
  }

  function countryPlace(code, cc) {
    var name = realCountry(cc);
    if (!name) return null;
    var upper = cc.toUpperCase();
    var city = CITY_STATES[upper] ? iata(CITY_STATES[upper]) : null;
    if (city && city.known && city.cc === upper) {
      return { code: code, city: city.city, cc: upper, lat: city.lat, lon: city.lon, known: true };
    }
    return { code: code, city: name, cc: upper, lat: null, lon: null, known: false };
  }

  /* 英文城市名 → 数据集里的代码。São Paulo / sao paulo / saopaulo 都归一成 saopaulo */
  function normName(value) {
    var text = String(value || '');
    if (text.normalize) text = text.normalize('NFD');
    return text.replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z]/g, '');
  }

  /* 两张索引随数据集一起建：英文城市名 → 代码（byName 用），中文城市 + 国家 → 同城全部代码（周边表用） */
  function buildIndexes() {
    nameIndex = {};
    cityIndex = {};
    Object.keys(colos).forEach(function (code) {
      var row = colos[code];
      if (!row) return;
      var key = normName(row[1]);
      /* 一城多机场（东京 NRT / HND / TYO）只记第一个：坐标差几十公里，不影响距离 */
      if (key && !nameIndex[key + '|' + row[2]]) nameIndex[key + '|' + row[2]] = code;
      if (key && !nameIndex[key]) nameIndex[key] = code;
      var city = (row[0] || row[1] || code) + '|' + row[2];
      (cityIndex[city] = cityIndex[city] || []).push(code);
    });
  }

  function byName(name, cc) {
    if (!nameIndex) buildIndexes();
    var hit = nameIndex[normName(name) + (cc ? '|' + cc.toUpperCase() : '')];
    if (!hit) return null;
    /* 按城市名查到的，代码是数据集里随手挑的一座机场（圣保罗可能是 CGH 也可能是 GRU），
       头里本来没有它——不显示，免得读的人以为 CDN 报的就是这个机场 */
    var info = iata(hit);
    info.code = '';
    return info;
  }

  /* 宽容地把一个「位置」头读成地点。认得的格式：
       HKG、hkg1、lax2-01        → 机场代码
       frankfurtDE、Frankfurt, DE → 城市 + 国家
       Frankfurt                  → 只有城市
     都认不出返回 null。 */
  function locate(value) {
    var raw = trim(value);
    if (!raw) return null;

    var m = /^([A-Za-z]{3})\d*(?:[-_.][\w.-]*)?$/.exec(raw);
    if (m) {
      var hit = knownIata(m[1]);
      if (hit) return hit;
    }

    /* 城市段必须以小写字母收尾：否则 HKG 会被拆成 H + 国家 KG */
    m = /^([A-Za-z][A-Za-z .'-]*[a-z])[\s,_-]*([A-Z]{2})$/.exec(raw);
    if (m) {
      var cc = m[2] === 'UK' ? 'GB' : m[2];
      var named = byName(m[1], cc);
      if (named) return named;
      var country = countryPlace(raw, cc);
      if (country) {
        /* 只认得国家时把头里的城市名带上；城市即国家的（新加坡）已经换成了城市，不必再拼 */
        if (!country.known) country.city = m[1].replace(/^\w/, function (c) { return c.toUpperCase(); }) + ' · ' + country.city;
        return country;
      }
    }

    return byName(raw, '');
  }

  /* ---------------------------------------------------------------- 解析器

     入参：values（要读的头 → 值，读不到是 null）、body（只有 trace / gcp 读正文）、row。
     返回：{ found, sub, place, label, ip, raw, odd }
       found  至少读到了一样相关的东西；false 就是「节点信息未开放」
       odd    读到了，但内容根本不是预期的那种东西（trace 回了一张 HTML 页面之类），值是给人看的原因
       sub    多 CDN 时实际接你的那一家（jsDelivr）
       place  地点；label 认不出地点时原样显示的节点名；ip 节点 IP
       raw    原始值，放进 title 方便对照 */

  function empty() {
    return { found: false, sub: '', place: null, label: '', ip: '', raw: '', odd: '' };
  }

  function seen(raw) {
    var out = empty();
    out.found = true;
    out.raw = trim(raw);
    return out;
  }

  /* 只取一个 IATA 代码的头：认得就是地点，认不得就原样显示 */
  function codeResult(out, code, fallback) {
    out.place = knownIata(code);
    if (!out.place) out.label = code ? code.toUpperCase() : shorten(fallback);
    return out;
  }

  /* Fastly 的 x-served-by：cache-fra-eddf8230159-FRA, cache-hkg17920-HKG —— 有回源屏蔽层时是两段，后一段才是你的边缘 */
  function fastlyCode(value) {
    var tokens = lastEntry(value).split('-');
    var code = tokens[tokens.length - 1] || '';
    return /^[A-Za-z]{3}$/.test(code) ? code : '';
  }

  var PARSERS = {
    trace: function (values, body) {
      if (body === null || trim(body) === '') return empty();
      var data = P.parseTrace(body);
      var out = seen('colo=' + (data.colo || ''));
      if (!data.colo) {
        /* 被劫持到登录页、拦截页时最常见：连上了，但回来的不是 Cloudflare 的 trace */
        out.raw = shorten(body);
        out.odd = '返回的不是 trace';
        return out;
      }
      return codeResult(out, data.colo, data.colo);
    },

    gcp: function (values, body, row) {
      var region = trim(body);
      if (!region) return empty();
      var out = seen(shorten(region));
      if (!/^[a-z]+-[a-z]+\d+$/.test(region)) {
        out.odd = '返回内容无法识别';
        return out;
      }
      var entry = row.regions ? row.regions[region] : null;
      if (entry) {
        out.place = { code: region, city: entry[0], cc: entry[1], lat: entry[2], lon: entry[3], known: true };
      } else {
        /* 新开的区域不在表里：原样显示区域名 */
        out.label = region;
      }
      return out;
    },

    jsdelivr: function (values) {
      var server = values.server;
      var ray = values['cf-ray'];
      var served = values['x-served-by'];
      var xid = values['x-id'];
      if (server === null && ray === null && served === null && xid === null) return empty();

      var out = seen([server, ray, served].filter(Boolean).join(' / '));
      if (ray || /cloudflare/i.test(server || '')) {
        /* cf-ray：8a1b2c3d4e5f6789-HKG，横杠后面就是 Cloudflare 机房 */
        out.sub = 'Cloudflare';
        var colo = ray ? trim(ray).split('-').pop() : '';
        return codeResult(out, /^[A-Za-z]{3}$/.test(colo) ? colo : '', ray || server);
      }
      if (served) {
        out.sub = 'Fastly';
        return codeResult(out, fastlyCode(served), served);
      }
      if (xid !== null || /g-?core/i.test(server || '')) {
        out.sub = 'G-Core';
        out.label = shorten(server || xid);
        return out;
      }
      out.sub = shorten(server) || '未知';
      out.label = '未能判断是哪一家';
      return out;
    },

    fastly: function (values) {
      var served = values['x-served-by'];
      if (served === null) return empty();
      return codeResult(seen(served), fastlyCode(served), served);
    },

    /* x-amz-cf-pop：NRT57-P4，前三位是机场代码 */
    cloudfront: function (values) {
      var pop = values['x-amz-cf-pop'];
      if (pop === null) return empty();
      var m = /^([A-Za-z]{3})/.exec(trim(pop));
      return codeResult(seen(pop), m ? m[1] : '', pop);
    },

    /* x-cache2 是 PerfOps 在 Akamai 上配的自定义头，竖线分隔，第三段是节点；格式没有公开文档，读不懂就原样显示 */
    akamai: function (values) {
      var value = values['x-cache2'];
      if (value === null) return empty();
      var out = seen(value);
      var parts = value.split('|').map(trim);
      out.ip = findIp(value);
      var candidate = parts.length > 2 ? parts[2] : '';
      out.place = candidate && !isIp(candidate) ? locate(candidate) : null;
      if (!out.place && !out.ip) out.label = shorten(candidate || value);
      return out;
    },

    /* server：BunnyCDN-JP1-1066 → 节点 JP1 */
    bunny: function (values) {
      var server = values.server;
      if (server === null) return empty();
      var out = seen(server);
      var m = /bunnycdn-([a-z]{2})(\d*)/i.exec(server);
      if (!m) {
        out.label = shorten(server);
        return out;
      }
      var code = (m[1] + m[2]).toUpperCase();
      var cc = BUNNY_CC[m[1].toUpperCase()];
      out.place = cc ? countryPlace(code, cc) : null;
      if (!out.place) out.label = code;
      return out;
    },

    /* x-cf1 是冒号分隔的一串，节点藏在形如 cacheN.lax2-01 的那一段里 */
    cachefly: function (values) {
      var value = values['x-cf1'];
      if (value === null) return empty();
      var out = seen(value);
      var parts = value.split(':');
      var code = '';
      var m = parts[3] ? /\.([A-Za-z]{3})\d*/.exec(parts[3]) : null;
      for (var i = 0; !m && i < parts.length; i++) {
        m = /\.([A-Za-z]{3})\d*(?:-\d+)?$/.exec(trim(parts[i]));
      }
      if (m) code = m[1];
      return codeResult(out, code, value);
    },

    location: function (values, body, row) {
      var value = null;
      for (var i = 0; i < row.headers.length && value === null; i++) value = values[row.headers[i]];
      if (value === null) return empty();
      var out = seen(value);
      out.place = locate(value);
      if (!out.place) out.label = shorten(value);
      return out;
    },

    /* Zenlayer 的 via 里节点写成「 LAX.xxx」。只看最后一跳，理由同下面的 via */
    zenlayer: function (values) {
      var via = values.via;
      if (via === null) return empty();
      var out = seen(via);
      var hop = lastEntry(via);
      var text = ' ' + hop;
      var re = /\s([A-Za-z]{3,})\.\w+/g;
      var m;
      var last = '';
      while ((m = re.exec(text)) !== null) last = m[1];
      if (last.length === 3) return codeResult(out, last, hop);
      out.label = shorten(last || hop || via);
      return out;
    },

    /* CDNetworks / QUANTIL 的 via：1.1 PS-NRT-01Hm8132:5 (Cdn Cache Server V2.0), 1.1 PS-HKG-… ——取最后一跳。
       正则只在最后一跳里找：在整串里取「最后一个匹配」的话，最后一跳没有代码（PS-000-…、不带横杠的 PSxxxx）时
       就会退到前面的回源层 / 屏蔽层，把别处的城市和距离安到你头上 */
    via: function (values) {
      var via = values.via !== null && values.via !== undefined ? values.via : values['x-via'];
      if (via === null || via === undefined) return empty();
      var out = seen(via);
      var hop = lastEntry(via);
      var m = /-([A-Za-z]{3})-/.exec(hop);
      /* 最后一跳认不出时，宁可原样显示它，也不拿前面的回源层冒充你的节点 */
      return codeResult(out, m ? m[1] : '', hop || via);
    },

    /* xcc：base64 编码的节点 IP */
    edgeone: function (values) {
      var value = values.xcc;
      if (value === null) return empty();
      var out = seen(value);
      var decoded = '';
      try { decoded = trim(window.atob(trim(value))); } catch (e) { decoded = ''; }
      /* 偶尔带着端口（1.2.3.4:443），去掉再判断 */
      var withPort = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(decoded);
      if (withPort) decoded = withPort[1];
      if (isIp(decoded)) out.ip = decoded;
      else out.label = shorten(value);
      return out;
    },

    /* via：cache12.l2cn1855[…], cache5.cn5130[0,0,200-0,H] —— 最后一跳是边缘，点号后面到方括号前是节点编号 */
    bytedance: function (values) {
      var via = values.via;
      if (via === null) return empty();
      var out = seen(via);
      var hop = lastEntry(via);
      var id = hop.indexOf('.') !== -1 ? hop.slice(hop.indexOf('.') + 1).replace(/\[.*$/, '').trim() : '';
      if (!id) {
        out.label = shorten(hop || via);
        return out;
      }
      out.label = shorten(id);
      /* 编号以国家代码开头时（cn、hk、sg……）标出国家；l1 / l2 是层级前缀，跳过 */
      var m = /^(?:l\d+)?([a-z]{2})\d/i.exec(id);
      if (m) out.place = countryPlace(id, m[1]);
      return out;
    },

    netease: function (values) {
      var ip = values['cdn-ip'];
      var source = values['cdn-source'];
      if (ip === null && source === null) return empty();
      var out = seen([ip, source].filter(Boolean).join(' / '));
      out.ip = findIp(ip);
      if (source) {
        out.sub = trim(source);
        for (var i = 0; i < VENDORS.length; i++) {
          if (VENDORS[i][0].test(trim(source))) {
            out.sub = VENDORS[i][1];
            break;
          }
        }
        out.sub = shorten(out.sub);
      }
      if (!out.ip && ip) out.label = shorten(ip);
      return out;
    }
  };

  /* 读到的原始头，一行一个「名字: 值」，放进节点格的 title——维护者对照解析对不对，不必打开开发者工具 */
  function headerDump(values) {
    return Object.keys(values).filter(function (name) {
      return values[name] !== null && values[name] !== undefined;
    }).map(function (name) {
      return name + ': ' + values[name];
    }).join('\n');
  }

  function parse(row, result) {
    var parser = PARSERS[row.parser];
    var out;
    if (!parser) return empty();
    try {
      out = parser(result.values, result.body, row);
    } catch (e) {
      /* 解析器自己出错也不能让这一行卡住：按「读到了但看不懂」处理，把原始值摆出来 */
      out = seen('');
      out.label = '无法解析';
    }
    var dump = headerDump(result.values);
    if (dump) out.raw = dump;
    return out;
  }

  /* ---------------------------------------------------------------- 探测

     resolve 永不 reject：
       { kind: 'ok', ms, status, values, body }   跨域请求成功（values 里读不到的头是 null）
       { kind: 'opaque', ms }                      跨域被拒，no-cors 连上了
       { kind: 'down', ms, reason }                超时 / 连接失败
       { kind: 'csp', ms }                         本页 CSP 没放行（部署漏改 nginx） */

  function probe(row) {
    var options = { method: row.method, mode: 'cors' };
    var needsBody = row.parser === 'trace' || row.parser === 'gcp';

    return P.request(row.url, options, TIMEOUT).then(function (first) {
      var response = first.response;
      var values = {};
      row.headers.forEach(function (name) {
        var value = null;
        try { value = response.headers.get(name); } catch (e) { value = null; }
        values[name] = value;
      });

      var body = needsBody
        ? within(response.text(), BODY_TIMEOUT, null).catch(function () { return null; })
        : drain(response);

      return body.then(function (text) {
        var base = { kind: 'ok', ms: first.ms, status: response.status, values: values, body: needsBody ? text : null };

        /* 第二次在热连接上测延迟；失败就退回第一次的耗时（偏大，但总比没有强） */
        return P.request(row.url, options, TIMEOUT).then(function (second) {
          drain(second.response);
          base.ms = second.ms;
          base.warm = true;
          return base;
        }, function () {
          return base;
        });
      });
    }, function (failure) {
      if (failure.kind === 'csp') return { kind: 'csp', ms: failure.ms };
      /* 跨域那一次都等满了 6 秒，no-cors 也不会更快，不再白等一轮 */
      if (failure.kind === 'timeout') return { kind: 'down', ms: failure.ms, reason: 'timeout' };

      return P.timing(row.url, {}, TIMEOUT).then(function (timing) {
        if (timing.ok) return { kind: 'opaque', ms: timing.ms };
        return { kind: timing.kind === 'csp' ? 'csp' : 'down', ms: timing.ms, reason: timing.kind };
      });
    });
  }

  /* ---------------------------------------------------------------- 渲染 */

  function km(place) {
    if (!visitor || !place || !place.known) return null;
    return P.distance(visitor.lat, visitor.lon, place.lat, place.lon);
  }

  function cityCodes(place) {
    if (!place.known) return [];
    if (!cityIndex) buildIndexes();
    return cityIndex[place.city + '|' + place.cc] || [];
  }

  /* 节点远近：规则在 probe.js（P.distanceClass），与 /cloudflare、首页同一套——
     有距离按距离、同国与周边表；没有距离只看同国与周边表，判不出就是 unknown（中性的「已识别」）。
     周边表按机场代码列（东京写的是 NRT），可这一页的地点不总带着那个代码：gcping 只给区域名，
     按城市名查到的只挑了一座机场（东京可能挑成 HND），Bunny 的 HK1 只知道在香港。
     所以把同城的每个代码都拿去对一遍：城市对上了就算，和 /cloudflare 上命中 NRT 的结论一致 */
  function classify(place) {
    /* 分档用 tier 而不是显示用的 country：/cloudflare 分档用的是 trace 报的国家，这里跟它用同一个 */
    var loc = visitor ? visitor.tier : '';
    var distance = km(place);
    var cls = P.distanceClass(place, loc, distance);
    var codes = cls === 'near' ? [] : cityCodes(place);
    for (var i = 0; i < codes.length; i++) {
      if (P.distanceClass({ code: codes[i], cc: place.cc }, loc, distance) === 'near') return 'near';
    }
    return cls;
  }

  /* 一行最终落在哪一档，verdict 与状态列共用：
     near / region / far / unknown 是读到了地点（P.DISTANCE_LABELS 的四档），read 是只读到编号或 IP */
  function outcome(row) {
    var result = row.result;
    if (!result) return 'pending';
    if (result.kind !== 'ok') return result.kind;
    var parsed = row.parsed;
    if (!parsed || !parsed.found) return 'hidden';
    if (parsed.odd) return 'odd';
    if (parsed.place) return classify(parsed.place);
    return 'read';
  }

  function placeLabel(place) {
    var flag = P.flag(place.cc);
    return (flag ? flag + ' ' : '') + place.city;
  }

  function thousands(n) {
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  function renderNode(row) {
    var cell = row.cells.node;
    var parsed = row.parsed;
    var kind = outcome(row);
    cell.removeAttribute('title');

    if (kind === 'opaque' || kind === 'hidden' || kind === 'odd') {
      fill(cell, [dim('仅测得延迟')]);
      if (kind === 'odd' && parsed && parsed.raw) cell.title = parsed.raw;
      return;
    }
    if (kind === 'down' || kind === 'csp' || kind === 'pending' || !parsed) {
      fill(cell, [dim('—')]);
      return;
    }

    var hit = P.el('div', 'cdnrow__hit');
    if (parsed.sub) hit.appendChild(P.el('span', 'tag tag--name', parsed.sub));
    if (parsed.place) {
      hit.appendChild(P.el('span', 'cdnrow__place', placeLabel(parsed.place)));
      if (parsed.place.code && parsed.place.code !== parsed.place.city) {
        hit.appendChild(P.el('span', 'cdnrow__code mono', parsed.place.code));
      }
    } else if (parsed.label) {
      hit.appendChild(P.el('span', 'cdnrow__code mono', parsed.label));
    }

    /* 节点 IP：有城市时作为补充放第二行；只拿到 IP（EdgeOne、网易）时它就是答案本身，提到第一行 */
    var ip = null;
    if (parsed.ip) {
      ip = P.el('span', 'cdnrow__ip');
      ip.appendChild(document.createTextNode('节点 IP '));
      var value = P.el('span', 'mono', P.compactIp(parsed.ip));
      if (value.textContent !== parsed.ip) value.title = parsed.ip;
      ip.appendChild(value);
    }

    var meta = [];
    var distance = km(parsed.place);
    if (distance !== null) meta.push(P.el('span', '', '约 ' + thousands(distance) + ' 公里'));
    if (ip && (parsed.place || parsed.label)) {
      meta.push(ip);
    } else if (ip) {
      ip.className = 'cdnrow__ip cdnrow__ip--main';
      hit.appendChild(ip);
    }

    var nodes = [];
    if (hit.childNodes.length) nodes.push(hit);
    if (meta.length) {
      var line = P.el('div', 'cdnrow__meta');
      meta.forEach(function (node) { line.appendChild(node); });
      nodes.push(line);
    }
    if (!nodes.length) nodes.push(dim('—'));
    fill(cell, nodes);

    /* 原始头值进 title：维护者对照解析是否正确，不必打开开发者工具 */
    if (parsed.raw) cell.title = parsed.raw;
  }

  function stateTag(text, tone, why) {
    var nodes = [P.el('span', 'tag ' + tone, text)];
    if (why) nodes.push(P.el('span', 'cdnrow__why', why));
    return nodes;
  }

  function renderState(row) {
    var kind = outcome(row);
    var result = row.result;
    var http = result && result.status >= 400 ? 'HTTP ' + result.status : '';
    var nodes;

    var label = P.DISTANCE_LABELS[kind];

    /* 判断不了远近的（已识别、已读取）一律中性灰：绿色只留给就近接入，
       否则同一列里绿色既表示「近」又表示「读到了但不知远近」，读的人会以为那家更好 */
    if (label) nodes = stateTag(label[0], 'tag--' + label[1]);
    else if (kind === 'read') nodes = stateTag('已读取', 'tag--muted');
    else if (kind === 'hidden') nodes = stateTag('可达', 'tag--muted', '节点信息未开放' + (http ? ' · ' + http : ''));
    else if (kind === 'opaque') nodes = stateTag('可达', 'tag--muted', '但不允许跨域读取');
    else if (kind === 'odd') nodes = stateTag('可达', 'tag--warn', row.parsed.odd);
    else if (kind === 'csp') nodes = stateTag(P.failureText('csp'), 'tag--leak');
    else if (kind === 'down') nodes = stateTag('不可达', 'tag--warn', P.failureText(result.reason));
    else nodes = [dim('待检测')];

    fill(row.cells.state, nodes);
  }

  function renderMs(row) {
    var cell = row.cells.ms;
    var result = row.result;
    cell.className = 'cdnrow__ms mono';
    if (!result || result.kind === 'down' || result.kind === 'csp') {
      cell.textContent = result ? '—' : '';
      return;
    }
    cell.textContent = result.ms + ' ms';
    cell.className += result.ms <= GOOD_MS ? ' is-good' : result.ms <= OK_MS ? ' is-ok' : ' is-slow';
    if (!result.warm) cell.title = '第二次请求没能完成，这是含握手的首次耗时';
    else cell.removeAttribute('title');
  }

  function renderRow(row) {
    renderNode(row);
    renderMs(row);
    renderState(row);
    row.node.classList.toggle('is-down', outcome(row) === 'down' || outcome(row) === 'csp');
  }

  function setPending(row, text) {
    row.result = null;
    row.parsed = null;
    row.node.classList.remove('is-down');
    fill(row.cells.node, [dim('—')]);
    row.cells.ms.className = 'cdnrow__ms mono';
    row.cells.ms.textContent = '';
    row.cells.ms.removeAttribute('title');
    row.cells.node.removeAttribute('title');
    fill(row.cells.state, [dim(text)]);
  }

  /* 「你当前命中」：只收认得出城市或国家的行，按页面顺序排 */
  function renderChips() {
    var chips = [];
    rows.forEach(function (row) {
      var parsed = row.parsed;
      if (!row.result || row.result.kind !== 'ok' || !parsed || !parsed.found || !parsed.place) return;
      var chip = P.el('span', 'cdnchip');
      chip.appendChild(P.el('span', 'cdnchip__name', row.name));
      chip.appendChild(P.el('span', 'cdnchip__place', placeLabel(parsed.place)));
      chips.push(chip);
    });

    if (chips.length) {
      fill(chipsCell, chips);
    } else {
      fill(chipsCell, [dim(running ? '检测中，读到节点的 CDN 会依次出现在这里。' : '没有读到任何一家 CDN 的节点城市。')]);
    }
  }

  function hasCoords() {
    return !!visitor && typeof visitor.lat === 'number' && typeof visitor.lon === 'number';
  }

  function renderWhere() {
    if (!whereCell) return;
    if (whereKind === 'loading') {
      /* 位置与出口两样都有了着落才合（settleVisitor）。还差哪一样就说哪一样：
         本站的回答已经到了、只差 Cloudflare 那一行的时候，不该还写着「正在向本站查询」 */
      if (me === undefined) {
        whereCell.textContent = '正在向本站查询你的大致位置，用来计算节点距离…';
      } else if (me) {
        whereCell.textContent = '本站已查到你的大致位置，正在等 Cloudflare 一行的 trace：核对它看到的出口是不是同一个之后，再计算节点距离…';
      } else {
        whereCell.textContent = '没能取到你的大致位置，正在等 Cloudflare 一行的 trace，看它报的出口在哪个国家/地区…';
      }
      return;
    }

    var country = visitor ? P.country(visitor.country) : '';
    /* 分档用的国家（见 settleVisitor）。多数时候和 country 是同一个 */
    var tier = visitor ? P.country(visitor.tier) : '';
    /* 没有坐标时还剩什么可依据：trace 报的国家 */
    var byCountry = country ? '，只按 Cloudflare 报的国家/地区（' + country + '）判断远近' : '';

    if (whereKind === 'other') {
      whereCell.textContent = 'Cloudflare 看到的出口与本站看到的不是同一个地址（多见于分流代理，或双栈网络下两边各走了一个地址族），'
        + '本站查到的位置不适用：本次不计算距离' + byCountry + '。';
      return;
    }
    if (whereKind === 'none') {
      whereCell.textContent = '没能取到你的大致位置（本站的归属查询暂时不可用），本次不计算距离' + byCountry + '。';
      return;
    }
    if (!hasCoords()) {
      whereCell.textContent = '本站没有查到你这条出口 IP 的坐标，本次不计算距离'
        + (tier ? '，只按国家/地区（' + tier + '）判断远近' : '') + '。';
      return;
    }

    /* 本站的记录一般带中文地名；只有英文名时，能在机房数据集里查到的换成中文（Tokyo → 东京）。
       没有城市才退到州 / 省。香港、新加坡这类城市即国家的，会和国家名重复，只留国家——
       国家名可能比城市名多个前缀（「中国香港」对「香港」），所以比的是结尾 */
    var place = visitor.city || visitor.region;
    var zh = visitor.city ? byName(visitor.city, visitor.country) : null;
    if (zh && zh.known) place = zh.city;
    var countryName = P.countryName(visitor.country);
    var parts = [];
    if (place && !(countryName && countryName.slice(-place.length) === place)) parts.push(place);
    if (country) parts.push(country);
    whereCell.textContent = '距离按本站查到的你的出口 IP 的大致位置计算：'
      + (parts.length ? parts.join(' · ') : '坐标 ' + visitor.lat + ', ' + visitor.lon) + '。'
      + (whereKind === 'unchecked'
        ? '这一轮没能读到 Cloudflare 的 trace，无法核对各家 CDN 看到的是不是这个出口；开着分流代理时，实际距离可能不同。'
        : '')
      /* 两家库对这条 IP 的国家说法不一时把话说明白：不然读的人会对不上——位置写着香港，东京的节点却算就近 */
      + (whereKind === 'ok' && visitor.tier !== visitor.country
        ? (tier
          ? 'Cloudflare 报的出口国家/地区是 ' + tier + '，与本站的记录不同；节点是否与你同在一个国家/地区、是否算周边，按 Cloudflare 报的判断，与 Cloudflare 节点检测一致。'
          : 'Cloudflare 没有报出这个出口所在的国家/地区，本次只按距离判断远近。')
        : '');
  }

  function names(list) {
    return list.map(function (row) { return row.name; }).join('、');
  }

  function renderVerdict(seconds) {
    var by = { near: [], region: [], far: [], unknown: [], read: [], hidden: [], opaque: [], odd: [], down: [], csp: [] };
    rows.forEach(function (row) {
      var kind = outcome(row);
      if (by[kind]) by[kind].push(row);
    });

    var identified = by.near.length + by.region.length + by.far.length + by.unknown.length + by.read.length;
    /* 判断得了远近的：有距离的，加上没有距离但同国 / 周边、直接算就近接入的 */
    var located = by.near.length + by.region.length + by.far.length;
    var limited = by.hidden.length + by.opaque.length + by.odd.length;
    var unreachable = by.down.length + by.csp.length;
    var tone;
    var title;
    var note;

    if (!identified) {
      if (unreachable === rows.length) {
        tone = 'is-bad';
        title = '所有 CDN 都连不上';
        note = '一家都没有响应。可能是网络断开、被防火墙或代理规则拦下，也可能是浏览器扩展（广告拦截、隐私保护）拦截了这些请求。';
      } else {
        tone = 'is-warn';
        title = '没能读到任何一家的节点';
        note = '能连上的 ' + limited + ' 家都没有把节点信息开放给其他网站，只测得延迟。'
             + '换一个网络或关掉拦截跨域请求的扩展后再试一次。';
      }
    } else if (located) {
      if (by.far.length && by.far.length * 2 >= located) {
        tone = 'is-warn';
        title = '多数 CDN 把你调度到了跨区节点';
        note = names(by.far) + ' 跨区接入：节点离你超过 ' + thousands(P.REGION_KM) + ' 公里，也不在你所在的国家/地区或周边。'
             + '常见原因：出口 IP 的归属与你的实际位置不符（代理 / VPN），DNS 用的是远处的解析器，'
             + '或者你的运营商与这些 CDN 之间缺少就近的互联。';
      } else {
        tone = 'is-good';
        /* 跨区的不到一半；就近的过半才说「就近」，否则只能说没有绕远（就近 + 区域内过半） */
        if (by.near.length * 2 < located) title = '多数 CDN 没有跨区调度';
        else title = by.far.length ? '大部分 CDN 就近调度' : 'CDN 调度基本就近';
        var spread = [];
        if (by.near.length) spread.push(by.near.length + ' 家就近接入');
        if (by.region.length) spread.push(by.region.length + ' 家在区域内');
        if (by.far.length) spread.push(by.far.length + ' 家跨区接入（' + names(by.far) + '）');
        note = located + ' 家能判断远近：' + spread.join('、') + '。';
      }
    } else {
      tone = 'is-good';
      title = '读到了 ' + identified + ' 家 CDN 的节点';
      note = hasCoords()
        ? '这几家只给出了国家、节点编号或节点 IP，没有城市坐标，暂不判断远近。'
        : (whereKind === 'other'
          ? '本站查到的位置不适用于 CDN 看到的这个出口，这几家暂不判断远近。'
          : '没能取到你的大致位置，暂不判断远近。');
    }

    var tail = [];
    if (identified && limited) tail.push(limited + ' 家只测得延迟（对方没有开放节点信息' + (by.odd.length ? '，或返回内容无法识别' : '') + '）');
    if (identified && by.down.length) tail.push(by.down.length + ' 家不可达');
    if (by.csp.length) tail.push(by.csp.length + ' 家被本站的内容安全策略拦下（' + names(by.csp) + '），这是部署配置的问题，不是你的网络');
    if (tail.length) note += '另有 ' + tail.join('，') + '。';

    verdict.className = 'verdict ' + tone;
    verdict.hidden = false;
    verdictTitle.textContent = title;
    verdictNote.textContent = note;

    if (progress) {
      progress.textContent = '完成：读到 ' + identified + ' 家的节点，' + limited + ' 家只测得延迟，'
        + unreachable + ' 家不可达，用时 ' + seconds + ' 秒。';
    }
  }

  /* ---------------------------------------------------------------- 主流程 */

  /* 页面上唯一会报出口 IP 的一行：Cloudflare 的 trace（清单里只有这一家读 trace） */
  var exitRow = null;
  rows.forEach(function (row) {
    if (!exitRow && row.parser === 'trace') exitRow = row;
  });

  function readExit(result) {
    if (!result || result.kind !== 'ok' || !result.body) return null;
    var data = P.parseTrace(result.body);
    if (!isIp(data.ip)) return null;
    /* loc 查不到时是 XX，Tor 出口是 T1：都不是国家 */
    var loc = trim(data.loc).toUpperCase();
    return { ip: trim(data.ip), loc: realCountry(loc) ? loc : '' };
  }

  /* me 说的是「本站看到的那条地址」，不是各家 CDN 看到的出口，拿 Cloudflare 报的出口核对一下再用：
       同一个出口（同一个 IPv4，或同一个 IPv6 /64）  me 的坐标可用，照常算距离
       不是同一个   分流代理把去 CDN 的流量送去了别的出口（或双栈下两边各走了一个地址族）：me 是另一条地址的位置，
                    拿来算距离只会得出一个看着很准的错数。不套用，只按 trace 报的国家判断远近
       trace 没读到（被扩展拦了、Cloudflare 不通）  无从核对。仍按 me 算，并在页面上明说没核对过——
                    其余各家本来也核对不了，这时和它们是同一个把握
       me 没取到    有 trace 就按它报的国家判断远近，都没有就不判
     两样都有了着落才合；先到的那个等一等，行里的距离晚一步补上（先按一样算、再改口的话，页面上的结论会跳）。

     分档用的国家（tier）与显示用的国家（country）分开记：
       country  和城市、坐标出自本站的同一条记录，「距离按什么算」那一行显示的是它；
       tier     读到了 trace 就用 trace 报的国家——/cloudflare 分档用的就是它，同一个出口、同一个节点，
                两页必须下同一个结论（两家库对边界上的地址、刚转卖过的网段常常各说各的）。
                trace 报不出国家（XX、Tor 的 T1）时就是空的，和 /cloudflare 一样只按距离分；trace 没读到才用本站记录里的国家。 */
  function settleVisitor(gen) {
    if (gen !== generation) return;
    if (me === undefined || exit === undefined) {
      /* 还差一样：先把「在等什么」那一行写准 */
      renderWhere();
      return;
    }

    var byCountry = exit && exit.loc ? { country: exit.loc, tier: exit.loc, lat: null, lon: null, region: '', city: '' } : null;

    if (me && exit && !P.sameIp(me.ip, exit.ip) && !P.samePrefix64(me.ip, exit.ip)) {
      visitor = byCountry;
      whereKind = 'other';
    } else if (me) {
      visitor = {
        country: me.country || (exit ? exit.loc : ''),
        tier: exit ? exit.loc : me.country,
        lat: me.lat, lon: me.lon, region: me.region, city: me.city
      };
      whereKind = exit ? 'ok' : 'unchecked';
    } else {
      visitor = byCountry;
      whereKind = 'none';
    }

    renderWhere();
    /* 位置晚到：已经出结果的行补上距离与远近 */
    rows.forEach(function (row) { if (row.result) renderRow(row); });
  }

  /* 本站对「它看到的你的地址」的位置记录（GeoApi 的 ?me=1），取不到就是 null。
     ready：机房数据集载入完毕。位置那一行可能要用它把英文城市名换成中文，所以等它一下（同源小文件，通常早就到了）。
     X-Requested-With 是给服务端认「这是本站页面上的脚本发的」用的（GeoApi::SCRIPT_HEADER，值是公开的）：
     不发 Sec-Fetch-Site 的旧浏览器里，服务端靠它把这一次请求和别的站点嵌的一张 <img> 分开。同源请求加头不触发预检 */
  function loadMe(gen, ready) {
    var text = function (v) { return typeof v === 'string' ? trim(v) : ''; };
    var asked = !meUrl ? Promise.resolve(null) : P.text(meUrl, { headers: { 'X-Requested-With': 'ipcx' } }, TIMEOUT).then(function (result) {
      var data = JSON.parse(result.text);
      if (!data || data.ok !== true || !isIp(text(data.ip))) return null;
      var lat = typeof data.lat === 'number' && isFinite(data.lat) ? data.lat : null;
      var lon = typeof data.lon === 'number' && isFinite(data.lon) ? data.lon : null;
      return {
        ip: text(data.ip),
        lat: lat !== null && lon !== null ? lat : null,
        lon: lat !== null && lon !== null ? lon : null,
        city: text(data.city),
        region: text(data.region),
        country: text(data.country).toUpperCase()
      };
    }).catch(function () {
      return null;
    });

    return asked.then(function (found) {
      return ready.then(function () { return found; });
    }).then(function (found) {
      /* 已经被主流程的兜底按「没取到」落定过了：迟到的结果不再改写 */
      if (gen !== generation || me !== undefined) return;
      me = found;
      settleVisitor(gen);
    });
  }

  function run() {
    if (running) return;
    running = true;
    generation++;
    var gen = generation;
    var started = P.now();
    var done = 0;

    /* 每轮都重新问位置与出口：两次检测之间切换代理、换网络正是这一页的常见用法 */
    me = undefined;
    exit = exitRow ? undefined : null;
    visitor = null;
    whereKind = 'loading';
    if (runButton) runButton.disabled = true;
    verdict.hidden = true;
    rows.forEach(function (row) { setPending(row, '排队中'); });
    renderChips();
    renderWhere();
    if (progress) progress.textContent = '检测中… 已完成 0 / ' + rows.length;

    var iataReady = P.iata(iataUrl).then(function (data) {
      if (data !== colos) {
        colos = data || {};
        nameIndex = null;
        cityIndex = null;
      }
    });
    var visitorReady = loadMe(gen, iataReady);
    var queue = P.queue(LANES);

    var jobs = rows.map(function (row) {
      return queue.add(function () {
        if (gen !== generation) return null;
        fill(row.cells.state, [dim('检测中…')]);
        return within(probe(row), ROW_DEADLINE, { kind: 'down', ms: ROW_DEADLINE, reason: 'timeout' });
      }).then(function (result) {
        return iataReady.then(function () { return result; });
      }).then(function (result) {
        if (gen !== generation || !result) return;
        row.result = result;
        row.parsed = result.kind === 'ok' ? parse(row, result) : null;
        renderRow(row);
        done++;
        if (progress) progress.textContent = '检测中… 已完成 ' + done + ' / ' + rows.length;
        renderChips();
        if (row === exitRow) {
          exit = readExit(result);
          settleVisitor(gen);
        }
      }).catch(function () {
        /* 走到这里只可能是渲染代码自己出了错：照样落定成「不可达」，不留一行「检测中」 */
        if (gen !== generation) return;
        row.result = { kind: 'down', ms: 0, reason: 'error' };
        row.parsed = null;
        renderRow(row);
      });
    });

    Promise.all(jobs).then(function () {
      return within(visitorReady, TIMEOUT, null);
    }).then(function () {
      if (gen !== generation) return;
      /* 兜底：到这里位置与出口都该有着落了。还悬着的（位置查询迟迟不归、trace 那一行出了错）按没取到落定，
         别让「正在查询你的大致位置」一直挂着，结论也好照着最终的位置来写 */
      if (me === undefined || exit === undefined) {
        if (me === undefined) me = null;
        if (exit === undefined) exit = null;
        settleVisitor(gen);
      }
      running = false;
      if (runButton) runButton.disabled = false;
      renderChips();
      renderVerdict(Math.max(1, Math.round((P.now() - started) / 1000)));
    }).catch(function () {
      /* 汇总渲染自己出了错也要把按钮还回去，不然这一页就再也测不了第二次 */
      running = false;
      if (runButton) runButton.disabled = false;
    });
  }

  if (runButton) runButton.addEventListener('click', run);
  run();
})();
