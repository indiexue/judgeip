import type { UsageType } from './asn-intelligence';

/* ASN 落地页解读文案：按网络类型撰写的深度解读框架，用真实数据填充。
   这是页面"内容价值"的核心——静态档案谁都有，场景化解读只有我们做。 */

export interface AsnCopy {
  whatIsIt: (zh: string, en: string) => string;
  riskView: (zh: string, en: string) => string;
  scenes: Array<{ zh: string; en: string; verdictZh: string; verdictEn: string; level: 'good' | 'warn' | 'bad' }>;
  caveat: (zh: string, en: string) => string;
}

const copy: Record<UsageType, AsnCopy> = {
  hosting: {
    whatIsIt: (zh, en) => zh === 'zh'
      ? '这是一个机房网络（数据中心 / 云厂商）自治系统。它对外宣告的 IP 段分配给云服务器、托管主机或基础设施服务使用，而不是家庭或移动用户。这类网络的流量几乎全部由机器产生：网页抓取、API 调用、代理中转、SaaS 服务后端，以及相当一部分的滥用行为。'
      : 'This is a hosting (data center / cloud provider) autonomous system. The prefixes it announces are assigned to cloud servers, hosted machines and infrastructure services rather than households or mobile users. Traffic from these networks is almost entirely machine-generated: crawling, API calls, proxy relays, SaaS backends — and a significant share of abuse.',
    riskView: (zh, en) => zh === 'zh'
      ? '平台风控对机房 IP 的默认态度是「提高警惕」而不是「直接封禁」。原因很直白：真人用户不会住在数据中心里。一个机房 IP 登录账号，要么用了代理/VPN（至少隐瞒了真实位置），要么根本就是程序在操作。所以跨境电商、支付、社媒这类重账号安全的平台会对机房 IP 加强验证甚至直接拒绝；而搜索引擎、AI 服务这类相对宽松的平台，只要该 IP 没有滥用记录，通常仍能正常使用。需要注意的是，机房 ASN 内部差异很大：同一家云厂商下，干净的服务器段和被滥用污染的段可能评分相差几十分。'
      : 'Risk engines treat hosting IPs with heightened scrutiny rather than outright bans, for a simple reason: real people do not live in data centers. A login from a hosting IP means either a proxy/VPN (hidden real location at minimum) or literal automation. Account-sensitive platforms — cross-border commerce, payments, social media — therefore challenge or refuse hosting IPs, while lenient services like search and AI usually work fine as long as the specific IP has no abuse record. Note that hosting ASNs are internally diverse: within the same cloud provider, a clean server range and an abuse-tainted one can score tens of points apart.',
    scenes: [
      { zh: '跨境电商（亚马逊/Shopify 等）', en: 'Cross-border commerce (Amazon/Shopify)', verdictZh: '不建议。店铺关联风控对机房 IP 极其敏感，极易触发审核或封号。', verdictEn: 'Not recommended. Store-linkage detection is extremely sensitive to hosting IPs.', level: 'bad' },
      { zh: '跨境支付（PayPal/Stripe 等）', en: 'Cross-border payments (PayPal/Stripe)', verdictZh: '不建议。支付风控会要求额外验证，甚至直接限制账号。', verdictEn: 'Not recommended. Payment risk engines demand extra verification or restrict accounts.', level: 'bad' },
      { zh: 'AI 服务（ChatGPT/Claude 等）', en: 'AI services (ChatGPT/Claude)', verdictZh: '能用但有条件。IP 干净时可用，被滥用污染的段会频繁验证或直接拒绝。', verdictEn: 'Conditional. Clean IPs work; abuse-tainted ranges face repeated challenges or refusal.', level: 'warn' },
      { zh: '流媒体解锁', en: 'Streaming unblocking', verdictZh: '多数不行。Netflix、Disney+ 等维护着活跃的机房段黑名单。', verdictEn: 'Mostly no. Netflix, Disney+ and others maintain active hosting-range blocklists.', level: 'bad' },
      { zh: '游戏联机', en: 'Gaming', verdictZh: '通常可以。游戏平台对网络类型基本不敏感，主要看延迟。', verdictEn: 'Usually fine. Game platforms rarely care about network type, only latency.', level: 'good' },
      { zh: '网页抓取 / 自动化', en: 'Web scraping / automation', verdictZh: '这本就是机房 IP 的本职，但要注意目标站点的反爬强度。', verdictEn: 'This is what hosting IPs are for — within the target site’s anti-bot tolerance.', level: 'good' },
    ],
    caveat: (zh, en) => zh === 'zh'
      ? '机房网络不等于「坏 IP」。云厂商的段同时承载着全球大量的正规互联网服务，评分低只说明它不适合模拟住宅用户场景。如果你就是在选购服务器或评估托管服务，机房 ASN 反而是正确选择——这时更应该关注的是该段是否被上游滥用记录污染，而不是它是不是机房。'
      : 'A hosting network does not mean a bad IP. Cloud ranges carry a large share of the legitimate internet; a low score only means the IP is unsuitable for impersonating residential users. If you are actually shopping for servers or evaluating hosting, a hosting ASN is the right choice — what matters then is whether the range is polluted by abuse records, not whether it is a data center.',
  },
  residential: {
    whatIsIt: (zh, en) => zh === 'zh'
      ? '这是一个住宅宽带网络自治系统，其 IP 段由运营商分配给家庭用户的宽带、光纤或电缆调制解调器。在风控视角里，住宅 IP 是「真实用户」的黄金标准：它们背后是实实在在付了网费的家庭，产生的流量以真人行为为主。'
      : 'This is a residential broadband autonomous system. Its prefixes are assigned by the carrier to household broadband, fiber or cable modems. To risk engines, residential IPs are the gold standard of a real user: behind them are homes that literally pay for internet service, and their traffic is overwhelmingly human.',
    riskView: (zh, en) => zh === 'zh'
      ? '平台风控对住宅 IP 的默认态度是信任。同一个住宅 IP 登录多个账号、进行支付或长期经营店铺，通常都不会因为 IP 本身被质疑——平台知道封掉住宅 IP 段等于封掉一大片真实用户，误伤成本太高。这也是「住宅代理」产业存在的原因：灰色产业同样需要住宅 IP 来伪装成真人。所以即使是住宅 ASN，单个 IP 的评分仍很重要：如果它同时被用作代理出口、出现在黑名单里，照样会被风控标记。评估住宅 IP 时，「原生注册」比「广播租用」更值得信赖，后者意味着这段地址其实是从别的地区甚至别的运营商转售过来的。'
      : 'Risk engines trust residential IPs by default. Multiple accounts, payments, or long-term store operation from the same residential IP rarely raise suspicion — platforms know that blocking residential ranges means blocking crowds of real users, an unacceptable false-positive cost. This is exactly why the residential-proxy industry exists: gray markets need residential IPs to look human too. So even within residential ASNs, per-IP scoring matters: an IP that doubles as a proxy exit or appears on blocklists still gets flagged. When evaluating residential IPs, natively registered ranges are more trustworthy than re-announced leased ones, which are resold from other regions or carriers.',
    scenes: [
      { zh: '跨境电商（亚马逊/Shopify 等）', en: 'Cross-border commerce (Amazon/Shopify)', verdictZh: '适合。原生住宅 IP 是店铺运营最稳妥的网络环境。', verdictEn: 'Suitable. Native residential IPs are the safest environment for store operation.', level: 'good' },
      { zh: '跨境支付（PayPal/Stripe 等）', en: 'Cross-border payments (PayPal/Stripe)', verdictZh: '适合。与家庭用户行为一致，风控通过率最高。', verdictEn: 'Suitable. Matches household behavior, highest pass rates.', level: 'good' },
      { zh: 'AI 服务（ChatGPT/Claude 等）', en: 'AI services (ChatGPT/Claude)', verdictZh: '适合。只要该 IP 未被滥用污染，住宅网络几乎不受限制。', verdictEn: 'Suitable. Unpolluted residential IPs face almost no restrictions.', level: 'good' },
      { zh: '流媒体解锁', en: 'Streaming unblocking', verdictZh: '适合。流媒体平台按地区授权内容，住宅 IP 是它们预期的观众来源。', verdictEn: 'Suitable. Streaming platforms license content by region and expect residential viewers.', level: 'good' },
      { zh: '社媒运营', en: 'Social media operation', verdictZh: '适合。多账号仍建议一户一 IP，但住宅网络本身不会成为封禁理由。', verdictEn: 'Suitable. One IP per account is still wise, but residential networks are never the reason for bans.', level: 'good' },
      { zh: '网页抓取 / 自动化', en: 'Web scraping / automation', verdictZh: '浪费。住宅带宽不适合高强度自动化，且容易把 IP 搞脏影响正常使用。', verdictEn: 'Wasteful. Residential bandwidth is wrong for heavy automation and easily gets the IP dirty.', level: 'warn' },
    ],
    caveat: (zh, en) => zh === 'zh'
      ? '住宅 ASN 里也有不干净的角落。运营商的段会被黑产盯上用于肉鸡和代理中转，所以单个 IP 是否出现在黑名单、是否有滥用记录，仍然需要逐条查证。「住宅」只是网络类型的 baseline 信任，不是免检金牌。'
      : 'Residential ASNs have dirty corners too. Carrier ranges get targeted for botnets and proxy relays, so whether a specific IP appears on blocklists or carries abuse records still needs checking. “Residential” is baseline trust by network type, not a blanket exemption.',
  },
  mobile: {
    whatIsIt: (zh, en) => zh === 'zh'
      ? '这是一个移动运营商网络自治系统，其 IP 段分配给手机蜂窝网络（4G/5G）用户。移动 IP 的特殊之处在于运营商普遍使用 CGNAT（运营商级 NAT）：成千上万个手机用户共享同一个公网出口 IP，单个 IP 背后的用户密度是所有网络类型里最高的。'
      : 'This is a mobile carrier autonomous system whose prefixes serve cellular (4G/5G) users. Mobile IPs are special because carriers widely deploy CGNAT: thousands of phone users share the same public exit IP, giving these addresses the highest user density of any network type.',
    riskView: (zh, en) => zh === 'zh'
      ? '平台风控对移动 IP 的态度是「信任但不可依赖」。信任是因为移动网络几乎必然是真人手机；不可依赖是因为 CGNAT 让「同一个 IP」几乎不具备识别意义——你无法判断这次的访问和上次是不是同一个用户，甚至无法判断是不是同一个运营商。部分平台因此会对移动 IP 的账号关联、设备识别打折扣。另外移动 IP 的地理定位精度通常只到城市群级别，跨省漫游时显示的归属地可能和实际位置相差很远。'
      : 'Risk engines treat mobile IPs as trusted but unreliable. Trusted because cellular traffic almost certainly means a real phone; unreliable because CGNAT makes the same IP meaningless for identification — you cannot tell whether two visits are the same user, or even the same subscriber at all. Some platforms discount account-linkage and device signals on mobile IPs accordingly. Geolocation is usually only accurate to the metro level, and roaming users can appear hundreds of kilometers from their actual location.',
    scenes: [
      { zh: '跨境电商', en: 'Cross-border commerce', verdictZh: '可以用但有讲究。适合移动端运营，不适合作为店铺固定登录环境。', verdictEn: 'Usable with caveats. Fine for mobile operation, wrong as a store’s fixed login environment.', level: 'warn' },
      { zh: '跨境支付', en: 'Cross-border payments', verdictZh: '通常可以。支付平台对移动网络的接受度很高。', verdictEn: 'Usually fine. Payment platforms accept mobile networks readily.', level: 'good' },
      { zh: 'AI 服务', en: 'AI services', verdictZh: '适合。移动 IP 极少被 AI 平台限制。', verdictEn: 'Suitable. Mobile IPs are rarely restricted by AI platforms.', level: 'good' },
      { zh: '社媒运营', en: 'Social media operation', verdictZh: '适合。社媒本来就是移动优先的平台，CGNAT 共享反而降低单 IP 关联风险。', verdictEn: 'Suitable. Social platforms are mobile-first, and CGNAT sharing actually dilutes per-IP linkage.', level: 'good' },
      { zh: '流媒体解锁', en: 'Streaming unblocking', verdictZh: '适合。但注意漫游时归属地可能飘到其他省份甚至国家。', verdictEn: 'Suitable. But roaming can shift the apparent location to another region entirely.', level: 'good' },
      { zh: '固定设备长期使用', en: 'Fixed-device long-term use', verdictZh: '不建议。移动 IP 会随基站切换频繁变化，不适合需要稳定出口的场景。', verdictEn: 'Not recommended. Mobile IPs shift with cell handover — wrong for anything needing a stable exit.', level: 'bad' },
    ],
    caveat: (zh, en) => zh === 'zh'
      ? '移动网络 IP 的「共享」属性是双刃剑：它让单个用户更难被追踪，但也意味着你的 IP 信誉由成千上万个陌生人共同决定。如果同一段 CGNAT 出口被滥用，即使你自己什么都没做，评分也可能受牵连。'
      : 'The shared nature of mobile IPs cuts both ways: it makes individual users harder to track, but it also means your IP reputation is collectively determined by thousands of strangers. If the CGNAT exit you share gets abused, your score suffers even though you did nothing.',
  },
  cdn: {
    whatIsIt: (zh, en) => zh === 'zh'
      ? '这是一个内容分发网络（CDN）或边缘计算平台的自治系统。它的 IP 段以 Anycast 方式在全球成百上千个节点同时宣告，同一个 IP 在不同地区会路由到不同的边缘节点。这些地址承载的是网站加速、安全防护和边缘计算流量，而不是终端用户。'
      : 'This is a content delivery network or edge platform autonomous system. Its prefixes are anycasted from hundreds or thousands of locations worldwide — the same IP routes to different edge nodes depending on where you are. These addresses carry website acceleration, security filtering and edge compute traffic, not end users.',
    riskView: (zh, en) => zh === 'zh'
      ? 'CDN 的 IP 在风控里有两种截然不同的身份。作为「服务方」时（比如某个网站套了 CDN），它们是互联网基础设施的正面角色；但当你的「客户端出口」是一个 CDN IP 时，问题就来了——正常用户的流量不会从 CDN 节点出来，这通常意味着你在使用 CDN 厂商的 VPN 产品（如 Cloudflare WARP）或者某种转发服务。平台风控对这种出口的态度取决于该 CDN 的滥用治理水平：治理严格的（如 Cloudflare）其出口 IP 信誉尚可，治理宽松的则可能整段被标记。'
      : 'CDN IPs play two very different roles in risk assessment. As server-side infrastructure (a website behind a CDN), they are a positive part of the internet. But when your client exit is a CDN IP, questions arise — normal users do not browse from CDN nodes, so it usually means a CDN-vendor VPN (like Cloudflare WARP) or some relay service. How risk engines treat such exits depends on the CDN’s abuse governance: well-governed ones (e.g. Cloudflare) keep decent exit reputation, loosely governed ones get entire ranges flagged.',
    scenes: [
      { zh: '跨境电商 / 支付', en: 'Commerce / payments', verdictZh: '不建议。CDN 出口会被视为代理类流量，账号安全验证强度明显升高。', verdictEn: 'Not recommended. CDN exits count as proxy-like traffic and invite heavier verification.', level: 'bad' },
      { zh: 'AI 服务', en: 'AI services', verdictZh: '多数能用。大型 CDN 厂商的出口在 AI 平台通常仍可接受，但稳定性不如住宅。', verdictEn: 'Mostly usable. Major CDN exits are often accepted by AI platforms, but less stable than residential.', level: 'warn' },
      { zh: '流媒体解锁', en: 'Streaming unblocking', verdictZh: '多数不行。流媒体对 CDN/机房段的封锁比对住宅严得多。', verdictEn: 'Mostly no. Streaming blocks CDN/hosting ranges far more aggressively than residential.', level: 'bad' },
      { zh: '日常浏览与开发', en: 'Daily browsing & development', verdictZh: '适合。CDN 出口速度快、延迟低，普通网页浏览和开发调试完全没问题。', verdictEn: 'Suitable. CDN exits are fast and low-latency — fine for browsing and development.', level: 'good' },
    ],
    caveat: (zh, en) => zh === 'zh'
      ? '判断一个 CDN IP 的用途要看场景：如果它是你访问的网站的 IP，那是再正常不过的基础设施；如果它是你自己的出口 IP，那才需要关心平台会怎么看待它。两者共用同一段地址，但含义完全不同。'
      : 'The meaning of a CDN IP depends on direction: as the address of a site you visit, it is perfectly normal infrastructure; as your own exit IP, it is what platforms will judge. The same range serves both, with completely different implications.',
  },
  business: {
    whatIsIt: (zh, en) => zh === 'zh'
      ? '这是一个企业/骨干网络自治系统，其 IP 段分配给公司、机构或骨干网互联使用。这类网络介于住宅和机房之间：它们产生的流量既有真实员工的使用，也有企业级服务的机器流量，平台风控对它的态度通常也介于两者之间。'
      : 'This is a business/backbone autonomous system whose prefixes are assigned to companies, institutions or backbone interconnection. These networks sit between residential and hosting: their traffic mixes real employee usage with enterprise machine traffic, and risk engines treat them accordingly.',
    riskView: (zh, en) => zh === 'zh'
      ? '骨干网（Tier-1/Transit）的段比较特殊：它们本身不是为终端用户服务的，但经常被转售、出租给下游 ISP 或商业 VPN 厂商。所以看到骨干网 IP 时，关键要查的是「这段具体宣告给谁用」——同一个骨干 ASN 下，原厂自用段、下游宽带段和 VPN 租用段的评分可能天差地别。大企业自用段的信誉通常不错，但被拆分出租的段往往是滥用重灾区。'
      : 'Backbone (Tier-1/transit) ranges are special: they were never meant for end users, but are constantly resold or leased to downstream ISPs and commercial VPN providers. So for a backbone IP, the key question is who the specific prefix is actually announced for — within the same backbone ASN, self-used corporate ranges, downstream broadband ranges and VPN-leased ranges can score worlds apart. Enterprise self-use is usually clean; subdivided leased blocks are often abuse hotspots.',
    scenes: [
      { zh: '跨境电商 / 支付', en: 'Commerce / payments', verdictZh: '看具体段。企业原生段尚可，租用段不建议。', verdictEn: 'Depends. Native enterprise ranges are passable; leased ranges are not.', level: 'warn' },
      { zh: 'AI 服务', en: 'AI services', verdictZh: '通常可以。除非该段被 VPN 滥用污染。', verdictEn: 'Usually fine, unless the range is polluted by VPN abuse.', level: 'warn' },
      { zh: '流媒体解锁', en: 'Streaming unblocking', verdictZh: '多数不行。骨干/商业段在流媒体黑名单里覆盖面很广。', verdictEn: 'Mostly no. Backbone/business ranges are widely covered by streaming blocklists.', level: 'bad' },
      { zh: '日常办公与开发', en: 'Office work & development', verdictZh: '适合。本来就是企业网络的本职场景。', verdictEn: 'Suitable. This is what enterprise networks are for.', level: 'good' },
    ],
    caveat: (zh, en) => zh === 'zh'
      ? '企业/骨干 ASN 是「一刀切」误判最严重的类型。评估时不能只看 ASN 级别，要下钻到具体前缀甚至单个 IP 的信誉记录——同一个 ASN 里，自建自用的段和对外出租的段完全是两个世界。'
      : 'Business/backbone ASNs suffer the most from blanket judgments. Never evaluate at the ASN level alone — drill down to the specific prefix or even single IP’s reputation. Within one ASN, self-used and leased-out ranges are two different worlds.',
  },
  education: {
    whatIsIt: (zh, en) => zh === 'zh'
      ? '这是一个教育/科研机构网络自治系统，其 IP 段分配给大学、科研院所的校园网。教育网的流量以师生真实使用为主，但也因为学生群体的特殊性（技术能力强、好奇心重、时间多），滥用比例略高于普通住宅网络。'
      : 'This is an education/research autonomous system whose prefixes serve university and institute campus networks. Education traffic is mostly real students and faculty, though abuse ratios run slightly higher than plain residential because of the student population — technically capable, curious, and with time on their hands.',
    riskView: (zh, en) => zh === 'zh'
      ? '平台风控对教育网的态度总体友好——它代表真实的机构用户。但教育网 IP 的地理属性比较特殊：大型大学的校区可能跨城市分布，且 IPv6 在教育网普及率极高，很多平台对教育网 IPv6 的地理库覆盖不全，容易出现归属地识别错误。'
      : 'Risk engines are generally friendly to education networks — they represent real institutional users. But education IPs have quirky geography: large universities span multiple cities, IPv6 adoption is exceptionally high, and many platforms have thin IPv6 geolocation coverage for them, producing frequent mislocations.',
    scenes: [
      { zh: 'AI 服务', en: 'AI services', verdictZh: '适合。教育网几乎不受 AI 平台限制。', verdictEn: 'Suitable. Education networks are rarely restricted by AI platforms.', level: 'good' },
      { zh: '跨境电商 / 支付', en: 'Commerce / payments', verdictZh: '可以用。但跨校区登录时注意保持 IP 稳定。', verdictEn: 'Usable, but keep the IP stable across campus logins.', level: 'warn' },
    ],
    caveat: (zh, en) => zh === 'zh'
      ? '教育网的身份认同很强，但前提是「真的是教育网在用」。部分学校会把闲置段出租给商业机构，租用段的信誉按实际用途重新评估。'
      : 'Education networks carry strong identity trust — as long as they are genuinely used by the institution. Some schools lease idle ranges commercially, and those are judged by their actual use instead.',
  },
  reserved: {
    whatIsIt: (zh, en) => zh === 'zh'
      ? '这是保留或特殊用途的网络段，不参与正常的公网路由评分。'
      : 'This is a reserved or special-purpose range, excluded from normal public routing evaluation.',
    riskView: (zh, en) => zh === 'zh'
      ? '保留段不参与评分，具体性质请查看 whois 原始记录。'
      : 'Reserved ranges are not scored; check the raw whois records for specifics.',
    scenes: [],
    caveat: (zh, en) => zh === 'zh' ? '' : '',
  },
};

export function asnCopy(type: UsageType): AsnCopy {
  return copy[type] || copy.business;
}
