/* /tiktok-ip 的「浏览器与这个 IP」一组：把浏览器的时区、语言和 IP 所在地对一下。
   这两项是设备上的设置，不计入打分表。IP 的时区和国家由服务端写在 data- 属性里。 */
(function () {
  'use strict';

  var root = document.querySelector('[data-sc-device]');
  if (!root) return;
  var T = window.T || function (zh) { return zh; };
  var tzCell = root.querySelector('[data-sc-timezone]');
  var langCell = root.querySelector('[data-sc-language]');
  var ipZone = root.getAttribute('data-ip-timezone') || '';
  var ipCountry = root.getAttribute('data-ip-country') || '';

  function fill(cell, tone, label, text) {
    cell.textContent = '';
    if (label) {
      var tag = document.createElement('span');
      tag.className = 'tag tag--' + tone;
      tag.textContent = label;
      cell.appendChild(tag);
      cell.appendChild(document.createTextNode(' '));
    }
    var span = document.createElement('span');
    if (!label) span.className = 'dim';
    span.textContent = text;
    cell.appendChild(span);
  }

  /* 某个时区此刻相对 UTC 的偏移（分钟）。时区名不认识时返回 null。 */
  function offsetMinutes(zone, now) {
    try {
      var parts = new Intl.DateTimeFormat('en-US', {
        timeZone: zone, hourCycle: 'h23',
        year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric'
      }).formatToParts(now);
      var v = {};
      parts.forEach(function (part) { v[part.type] = Number(part.value); });
      return Math.round((Date.UTC(v.year, v.month - 1, v.day, v.hour, v.minute, v.second) - now.getTime()) / 60000);
    } catch (e) {
      return null;
    }
  }

  function utcLabel(minutes) {
    var abs = Math.abs(minutes);
    var mm = abs % 60;
    return 'UTC' + (minutes < 0 ? '-' : '+') + Math.floor(abs / 60) + (mm ? ':' + (mm < 10 ? '0' : '') + mm : '');
  }

  function checkTimezone() {
    var zone = '';
    try { zone = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) {}
    var now = new Date();
    var mine = zone ? offsetMinutes(zone, now) : null;
    var theirs = ipZone && ipZone !== '—' ? offsetMinutes(ipZone, now) : null;
    if (mine === null) return fill(tzCell, '', '', T('读不到浏览器时区', 'Browser time zone unavailable'));
    if (theirs === null) return fill(tzCell, '', '', T('浏览器 ', 'Browser ') + zone + ' (' + utcLabel(mine) + ')' + T('，IP 的时区未知', '; IP time zone unknown'));
    var text = T('浏览器 ', 'Browser ') + zone + ' (' + utcLabel(mine) + ') · IP ' + ipZone + ' (' + utcLabel(theirs) + ')';
    if (mine === theirs) fill(tzCell, 'ok', T('一致', 'Match'), text);
    else fill(tzCell, 'warn', T('不一致', 'Mismatch'), text);
  }

  function checkLanguage() {
    var list = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || ''];
    var langs = Array.prototype.slice.call(list, 0, 3).filter(Boolean);
    if (!langs.length) return fill(langCell, '', '', T('读不到浏览器语言', 'Browser language unavailable'));
    var text = langs.join(', ') + (ipCountry ? ' · IP ' + ipCountry : '');
    if (!ipCountry) return fill(langCell, '', '', text + T(' · IP 的国家未知', ' · IP country unknown'));
    /* 只标一种情况：首选语言是简体中文，IP 却不在常用简体中文的地区 */
    var simplified = /^zh(-Hans|-CN|$)/i.test(langs[0]);
    if (simplified && ['CN', 'HK', 'MO', 'TW', 'SG', 'MY'].indexOf(ipCountry) === -1) {
      fill(langCell, 'warn', T('不一致', 'Mismatch'), text + T(' · 首选语言是简体中文', ' · first language is Simplified Chinese'));
    } else {
      fill(langCell, 'muted', T('未见差异', 'Nothing flagged'), text);
    }
  }

  checkTimezone();
  checkLanguage();
})();
