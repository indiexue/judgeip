import type { APIRoute } from 'astro';
import { extractVisitorIp, parseIp } from '../../../lib/ip-utils';
import { lookupIpFull } from '../../../lib/ipcx-lookup';
import { localizeLookup } from '../../../lib/lookup-en';
import { lookupLimitedResponse, rateHeaders, rateLimit } from '../../../lib/rate-limit';

// Keep the legacy envelope, but use the same evidence and score as the site/CLI/MCP.
export const GET: APIRoute = async ({ request, url }) => {
  const targetParam = url.searchParams.get('ip')?.trim();
  const visitorIp = extractVisitorIp(request);
  const parsed = parseIp(targetParam && targetParam !== 'me' ? targetParam : visitorIp);
  const headers = { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' };
  if (!parsed) return new Response(JSON.stringify({ ok: false, error: 'Invalid IPv4 or IPv6 address format.' }), { status: 400, headers });
  const rate = rateLimit('api', visitorIp);
  if (!rate.ok) return lookupLimitedResponse(rate.resetIn, { ...headers, ...rateHeaders(rate) });
  const started = Date.now();
  const isVisitor = parsed.normalized === visitorIp;
  try {
    const cf = (request as Request & { cf?: Record<string, unknown> }).cf || null;
    const info = await lookupIpFull(parsed.normalized, cf, isVisitor, null, { visitorIp });
    if (info.lookupStatus === 'limited') return lookupLimitedResponse(info.retryAfter, headers);
    const en = localizeLookup(info, 'en');
    const titleZh = info.hasThreat === true ? '发现风险，谨慎使用' : '规则参考，需核验信誉覆盖';
    const titleEn = info.hasThreat === true ? 'Risk detected; use caution' : 'Rule-based estimate; review reputation coverage';
    const report = {
      ip: info.ip, version: info.version, evaluatedAt: new Date().toISOString(), latencyMs: Date.now() - started,
      score: info.score, grade: info.grade, scoringVersion: info.scoringVersion,
      // The old complement was not a measured fraud probability. Do not publish it as one.
      fraudRisk: null, fraudRiskNote: 'Deprecated: this rule score is not a fraud probability.',
      riskLevel: info.hasThreat === true || info.isProxy === true ? 'high' : info.hasThreat === null ? 'unknown' : 'low',
      verdictTitleZh: titleZh, verdictTitleEn: titleEn, verdictSummaryZh: info.threatLabel, verdictSummaryEn: en.threatLabel,
      scoreConfidence: info.scoreConfidence, reputationCoverage: info.reputationCoverage, reputationChecks: info.reputationChecks,
      geo: { countryCode: info.countryCode, countryName: info.countryZh, region: info.region, city: info.city, latitude: info.latitude, longitude: info.longitude, timezone: info.timezone },
      network: { asn: info.asn, asnCode: info.asnCode, isp: info.isp, org: info.org, domain: info.domain, usageType: info.usageType, rirCountryCode: info.rirCountry, nativeStatus: info.isNative === null ? 'unknown' : info.isNative ? 'native' : 'broadcast' },
      signals: { isDatacenter: info.isDatacenter, isProxyOrVpn: info.isProxy, isAbuserOrCrawler: info.hasThreat, hasExposedProxyPorts: info.portsKnown ? info.proxyPorts.length > 0 : null, openPorts: info.openPorts, vulnsCount: info.vulnsCount },
      scoreBase: info.scoreBase,
      factors: info.factors.map((f, i) => ({ id: f.key, delta: f.delta, severity: f.tone === 'leak' ? 'bad' : f.tone === 'ok' ? 'good' : f.tone === 'warn' ? 'warn' : 'info', titleZh: f.label, titleEn: en.factors[i].label, detailZh: f.status, detailEn: en.factors[i].status, evidence: f.evidence })),
      platforms: info.scenes.map((scene, i) => ({ id: scene.key, nameZh: scene.label, nameEn: en.scenes[i].label, status: scene.tone === 'leak' ? 'block' : 'warn', badgeZh: scene.status, badgeEn: en.scenes[i].status, reasonZh: scene.note, reasonEn: en.scenes[i].note })),
      sources: [...new Set(info.factors.flatMap((f) => f.evidence.map((e) => e.source)))],
    };
    return new Response(JSON.stringify({ ok: true, isVisitor, report }), { headers: { ...headers, ...rateHeaders(rate) } });
  } catch {
    return new Response(JSON.stringify({ ok: false, error: 'Failed to evaluate IP evidence' }), { status: 500, headers });
  }
};
