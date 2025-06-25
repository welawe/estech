require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const { createProxyMiddleware } = require('http-proxy-middleware');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;
const crawlers = require('crawler-user-agents');

// Configuration

const API_KEYS = new Set(process.env.API_KEYS?.split(',') || ['ADMIN']);
const IPWHOIS_API = 'http://ipwho.is/';
const TOR_EXIT_NODES_URL = 'https://check.torproject.org/torbulkexitlist';
const KNOWN_VPN_IPS_URL = 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt';
const MALICIOUS_IP_URL = 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt';
const HOSTNAME_BLACKLIST_URL = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts';
const THREAT_URLS_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api/', limiter);

// Cache for TOR and VPN IPs
let torExitNodes = new Set();
let vpnIpRanges = new Set();
let maliciousIps = new Set();
let hostnameBlacklist = new Set();
let threatUrls = new Set();

// Request timing tracking
const requestTimingMap = new Map();

// Load block lists
async function loadBlockLists() {
  try {
    // Load existing lists
    await Promise.all([
      // Existing TOR and VPN loads
      (async () => {
        const torResponse = await fetch(TOR_EXIT_NODES_URL);
        const torList = await torResponse.text();
        torExitNodes = new Set(torList.split('\n').filter(ip => ip.trim() !== ''));
      })(),
      (async () => {
        const vpnResponse = await fetch(KNOWN_VPN_IPS_URL);
        const vpnList = await vpnResponse.text();
        vpnIpRanges = new Set(vpnList.split('\n').filter(ip => ip.trim() !== ''));
      })(),
      
      // Load malicious IPs
      // Load malicious IPs - PERBAIKAN DI SINI
      (async () => {
        const response = await fetch(MALICIOUS_IP_URL);
        const data = await response.text();
        maliciousIps = new Set(
          data.split('\n')
            .filter(line => !line.startsWith('#') && line.trim() !== '')
            .map(line => line.split('\t')[0].trim()) // Ambil kolom pertama (IP)
            .filter(ip => ip) // Pastikan IP tidak kosong
        );
      })(),
      
      // Load hostname blacklist
      (async () => {
        const response = await fetch(HOSTNAME_BLACKLIST_URL);
        const data = await response.text();
        hostnameBlacklist = new Set(
          data.split('\n')
            .filter(line => !line.startsWith('#'))
            .map(line => line.split(' ')[1])
            .filter(host => host)
        );
      })(),
      
      // Load threat URLs
      (async () => {
        const response = await fetch(THREAT_URLS_URL);
        const data = await response.text();
        threatUrls = new Set(
          data.split('\n')
            .filter(line => line.trim() !== '')
            .map(url => {
              try {
                return new URL(url.trim()).hostname;
              } catch {
                return null;
              }
            })
            .filter(host => host)
        );
      })()
    ]);
    
    console.log(`Loaded ${torExitNodes.size} TOR exit nodes, ${vpnIpRanges.size} VPN IPs, ` +
      `${maliciousIps.size} malicious IPs, ${hostnameBlacklist.size} blacklisted hosts, ` +
      `${threatUrls.size} threat URLs`);
  } catch (error) {
    console.error('Error loading block lists:', error);
  }
}

// Load block lists on startup and refresh every 6 hours
loadBlockLists();
setInterval(loadBlockLists, 6 * 60 * 60 * 1000);

// API key validation
function validateApiKey(req, res, next) {
  const apiKey = req.query.api_key || req.headers['x-api-key'];
  if (!apiKey || !API_KEYS.has(apiKey)) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid or missing API key'
    });
  }
  next();
}

// Add this function near the other detection functions
async function detectDataCenter(ip) {
  if (!ip) return { is_datacenter: false, details: null };

  try {
    const response = await fetch(`${IPWHOIS_API}${ip}`);
    const data = await response.json();
    
    const isDatacenter = data?.connection?.org?.toLowerCase().includes('data center') || 
                        data?.connection?.org?.toLowerCase().includes('datacenter') ||
                        data?.connection?.isp?.toLowerCase().includes('data center') ||
                        data?.connection?.isp?.toLowerCase().includes('datacenter') ||
                        data?.connection?.org?.toLowerCase().includes('amazon') ||
                        data?.connection?.org?.toLowerCase().includes('google') ||
                        data?.connection?.org?.toLowerCase().includes('microsoft') ||
                        data?.connection?.org?.toLowerCase().includes('digitalocean') ||
                        data?.connection?.org?.toLowerCase().includes('linode') ||
                        data?.connection?.org?.toLowerCase().includes('vultr') ||
                        data?.connection?.org?.toLowerCase().includes('ovh') ||
                        data?.connection?.org?.toLowerCase().includes('hetzner') ||
                        data?.connection?.org?.toLowerCase().includes('alibaba') ||
                        data?.connection?.org?.toLowerCase().includes('tencent');

    return {
      is_datacenter: isDatacenter || false,
      details: {
        asn: data?.connection?.asn,
        org: data?.connection?.org,
        isp: data?.connection?.isp,
        type: data?.connection?.type
      }
    };
  } catch (error) {
    console.error('Error checking data center:', error);
    return {
      is_datacenter: false,
      details: null
    };
  }
}

async function enhancedDetection(ip, hostname) {
  // 1. Check IP blacklist
  const isBlacklistedIp = maliciousIps.has(ip) || 
    Array.from(maliciousIps).some(range => range.includes('/') && isIpInRange(ip, range));
  
  // 2. Check hostname blacklist
  const isBlacklistedHost = hostname && hostnameBlacklist.has(hostname.toLowerCase());
  
  // 3. Check threat URLs
  const isThreatUrl = hostname && threatUrls.has(hostname.toLowerCase());
  
  // 4. Existing VPN/TOR detection
  const vpnTorInfo = await detectVpnOrTor(ip);

  const dataCenterInfo = await detectDataCenter(ip);
  
  return {
    is_blacklisted_ip: isBlacklistedIp,
    is_blacklisted_host: isBlacklistedHost,
    is_threat_url: isThreatUrl,
    is_datacenter: dataCenterInfo.is_datacenter,
    datacenter_details: dataCenterInfo.details,
    ...vpnTorInfo,
    threats_detected: isBlacklistedIp || isBlacklistedHost || isThreatUrl || 
                     vpnTorInfo.is_vpn || vpnTorInfo.is_tor || vpnTorInfo.is_proxy ||
                     dataCenterInfo.is_datacenter
  };
}

// VPN/TOR detection
async function detectVpnOrTor(ip) {
  if (!ip) return { is_vpn: false, is_tor: false, is_proxy: false };
  
  // Check local blocklists first
  const isTor = torExitNodes.has(ip);
  const isVpn = Array.from(vpnIpRanges).some(range => {
    if (range.includes('/')) {
      return isIpInRange(ip, range);
    }
    return ip === range;
  });
  
  if (isTor || isVpn) {
    return {
      is_vpn: isVpn,
      is_tor: isTor,
      is_proxy: isVpn || isTor,
      method: 'local_blocklist'
    };
  }
  
  // Fallback to ipwho.is
  try {
    const response = await fetch(`${IPWHOIS_API}${ip}`);
    const data = await response.json();
    
    return {
      is_vpn: data?.connection?.vpn || false,
      is_tor: data?.connection?.tor || false,
      is_proxy: data?.connection?.proxy || false,
      method: 'ipwhois_api',
      details: {
        isp: data?.connection?.isp,
        org: data?.connection?.org,
        asn: data?.connection?.asn
      }
    };
  } catch (error) {
    console.error('Error checking VPN/TOR:', error);
    return {
      is_vpn: false,
      is_tor: false,
      is_proxy: false,
      method: 'error'
    };
  }
}

// CIDR range check helper
function isIpInRange(ip, cidr) {
  const [range, bits] = cidr.split('/');
  const mask = (~0 << (32 - bits)) >>> 0;
  const ipLong = ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  const rangeLong = range.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  return (ipLong & mask) === (rangeLong & mask);
}

// Enhanced bot detection with all requested features
// Enhanced bot detection with new scoring system
function isRequestFromBot(req) {
    // Initialize scoring with the new weighting system
    let botScore = 0;
    const threshold = 70;
    
    // Extract all relevant information
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const host = req.headers['host'] || '';
    const accept = req.headers['accept'] || '';
    const connection = req.headers['connection'] || '';
    const via = req.headers['via'] || '';
    const xForwardedFor = req.headers['x-forwarded-for'] || '';
    const referer = req.headers['referer'] || '';
    const cookies = req.headers['cookie'] || '';
    const acceptLanguage = req.headers['accept-language'] || '';
    const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const httpVersion = req.httpVersion;
    const path = req.path || '';
    const query = req.query || {};
    
    // Safe TLS info extraction
    let tlsInfo = {};
    try {
        if (req.socket) {
            tlsInfo = {
                name: typeof req.socket.getCipher === 'function' ? req.socket.getCipher()?.name : null,
                version: req.socket.getProtocol ? req.socket.getProtocol() : null,
                encrypted: req.socket.encrypted
            };
        }
    } catch (error) {
        console.error('Error extracting TLS info:', error);
    }

    // Result object
    const result = {
        isBot: false,
        isBlock: false,
        score: 0,
        reasons: [],
        details: {
            userAgent,
            ip,
            httpVersion,
            tlsInfo,
            headers: {
                host,
                accept,
                connection,
                via,
                xForwardedFor,
                referer,
                cookies,
                acceptLanguage
            }
        }
    };
    
    // 1. Known Bot Patterns (50 points)
    const botPatterns = [
        // Security bots
        'google-safe-browsing', 'google-transparency-report', 'phishtank', 'openphish', 
        'safebrowsing', 'urlscan', 'virustotal', 'phishfort', 'certly', 'phishcatch',
        'phishai', 'phishdetect', 'netcraft', 'zvelo', 'cleantalk', 'sucuri', 'quttera',
        'malwarebytes', 'cloudflare-radar', 'akamai-bot', 'fastly-security', 'imperva',
        'incapsula', 'barracuda', 'fortiguard', 'microsoft-safelink', 'safari-fraud-detection',
        'chrome-phishing-protection', 'edge-smartscreen', 'abuse.ch', 'threatintelligence',
        'cyberpatrol', 'trustedsource', 'websense', 'bluecoat', 'mcafee', 'symantec',
        'kaspersky', 'trendmicro', 'f-secure', 'paloalto', 'checkpoint', 'sophos', 'bitdefender',
        
        // Email providers
        'microsoft-exchange', 'outlook-protection', 'google-mail', 'gmail', 'yahoo-mail', 
        'protonmail', 'tutanota', 'mail.ru', 'zoho-mail', 'fastmail', 'icloud-mail',
        'aol-mail', 'mailchimp', 'sendgrid', 'mandrill', 'postmark', 'sparkpost', 'mailgun',
        'amazon-ses', 'proofpoint', 'mimecast', 'barracuda-email', 'ironport', 'symantec-email',
        'trendmicro-email', 'fortimail', 'mail.com', 'mail-com', 'mailcom', '1and1-mail', '1und1',
        'mx-login.mail.com', 'webmail.mail.com', 'mailer.mail.com', 'mail-checker', 'mail-scanner',
        'mail.com', 'mailcom-guardian','mx-login.mail.com', 'mailcom-spam-checker',
        'webmail.mail.com', 'mailcom-spam-checker','mailgun-mail-filter',
        'mailer.mail.com', 'mailcom-spam-checker',
        'mail-checker', 'generic-mail-checker',
        'mail-scanner', 'generic-mail-scanner',
        'mail-com', 'mailcom-guardian',
        'mailcom', 'mailcom-guardian',
        
        // Domain/DNS related
        'verisign', 'nic.', 'registry', 'iana', 'icann', 'afilias', 'publicinterestregistry',
        'donuts', 'centralnic', 'neustar', 'nominet', 'kisa', 'twnic', 'godaddy', 'namecheap',
        'enom', 'network solutions', 'porkbun', 'name.com', 'google domains', 'cloudflare registrar',
        'dynadot', 'hexonet', 'key-systems', 'resellerclub', 'eurodns', 'ovh', 'hostinger',
        'bluehost', 'hostgator', 'cocca', 'dotasia', 'corenic', 'registry.google', 'domain-check',
        'whois', 'dns-check', 'registry-bot', 'tld-scanner', 'domain-scanner', 'sld-monitor',
        
        // Generic bot patterns
        'bot', 'crawl', 'spider', 'scanner', 'monitor', 'checker', 'validator', 'fetcher',
        'collector', 'analyzer', 'indexer', 'extractor', 'reader', 'watcher', 'tracker',
        'sniffer', 'harvester', 'headlesschrome', 'headlessfirefox', 'phantomjs', 'puppeteer',
        'playwright', 'selenium', 'webdriver', 'ahrefs', 'semrush', 'seokicks',
        'seoscanners', 'screaming frog', 'sitebulb', 'deepcrawl', 'netsparker', 'httrack',
        'wget', 'curl', 'python-requests', 'pingdom', 'uptimerobot', 'newrelic', 'datadog',
        'statuscake', 'site24x7', 'gtmetrix', 'webpagetest', 'facebookexternalhit', 'twitterbot',
        'linkedinbot', 'slackbot', 'discordbot', 'telegrambot', 'whatsapp', 'feedfetcher',
        'feedparser', 'rss', 'atom', 'syndication', 'bytespider', 'petalbot', 'applebot',
        'bingbot', 'yandexbot', 'duckduckbot',
    
        // NEW: WHOIS/DNS lookup tools
        'whois', 'dnsdumpster', 'dnstrails', 'dnslytics', 'viewdns',
        'mxtoolbox', 'dnscheck', 'dig', 'nslookup', 'whoisxmlapi',
        'whoxy', 'domaintools', 'robtex', 'bgp.he', 'ipinfo.io',
        
        // NEW: Domain registry bots
        // Domain Registry Bots (Complete List)
'registrar', 'registry', 'domaincheck', 'domainmonitor', 'domaintools',
'markmonitor', 'brandprotect', 'corsearch', 'trademarknow', 'brandshield',
'comlaude', 'cscglobal', 'eurodns', 'key-systems', 'melbourneit',
'networksolutions', 'publicdomainregistry', 'resellerclub', 'safenames',
'tucows', 'uniregistry', 'web.com', 'namecheap', 'godaddy', 'enom',
'resell.biz', 'opensrs', 'hexonet', 'internet.bs', 'verisign', 'identitydigital',
'centralnic', 'donuts', 'afilias', 'pir.org', 'icann', 'iana', 'nominet',
'kisa', 'twnic', 'corenic', 'redpoints', 'pointerbrandprotection', 'appdetex',
'whiteops', 'dnstwist', 'whoisxmlapi', 'whoxy', 'whois', 'dnsdumpster',
'dnstrails', 'dnslytics', 'viewdns', 'mxtoolbox', 'bgp.he', 'ipinfo.io',
'robtex', 'circl.lu', 'farsightsecurity', 'domainrecon', 'domaintally',
'brandsnap', 'namestall', 'domainpunch', 'whoisology', 'domainiq',
'registrarstats', 'registrybot', 'tldwatch', 'sldscanner', 'nicbot',
'whoisbot', 'domaincrawler', 'brandmonitor', 'trademarkbot', 'dnmonitor',
'whoisguard', 'whoisprivacy', 'domaindefender', 'brandverity', 'digicert',
'sectigo', 'entrust', 'globalsign', 'certum', 'trustprovider', 'certbot',
'letsencrypt', 'zerossl', 'sslbot', 'certchecker', 'domainpulse',
'whoisguardian', 'dnshield', 'brandwatchbot', 'trademarkcrawler'
    ];
    
    botPatterns.forEach(pattern => {
        if (userAgent.includes(pattern)) {
            botScore += 55;
            result.reasons.push(`Known bot pattern detected: ${pattern}`);
        }
    });
    
    // 2. Behavioral Anomalies (30 points)
    const behavioralPatterns = {
        automationSignatures: userAgent.includes('phantomjs') || 
                            userAgent.includes('puppeteer') ||
                            userAgent.includes('playwright') ||
                            userAgent.includes('selenium') ||
                            userAgent.includes('webdriver'),
        unusualBehavior: (req.headers['dnt'] === '1' && !userAgent.includes('firefox')) ||
                       (req.headers['upgrade-insecure-requests'] === '1' && !userAgent.includes('chrome')) ||
                       (req.headers['save-data'] === 'on' && !userAgent.match(/chrome|opera/i)),
        http1Usage: httpVersion === '1.1' && !userAgent.match(/curl|wget|python|java|go-http/i)
    };
    
    if (behavioralPatterns.automationSignatures) {
        botScore += 30;
        result.reasons.push("Known automation tool signature detected");
    }
    
    if (behavioralPatterns.unusualBehavior) {
        botScore += 15;
        result.reasons.push("Unusual browser behavior pattern detected");
    }
    
    if (behavioralPatterns.http1Usage) {
        botScore += 10;
        result.reasons.push("Suspicious HTTP/1.1 usage (possible older automation tool)");
    }

    if (req.datacenterInfo?.is_datacenter) {
    botScore += 25;
    result.reasons.push("Request from known data center IP");
    result.details.datacenter = req.datacenterInfo.details;
    }

    if (req.vpnTorInfo?.is_proxy) {
    botScore += 30;
    result.reasons.push("Request from proxy/VPN/Tor network");
    result.details.proxyInfo = req.vpnTorInfo;
    }   
    
    // 3. TLS Fingerprinting (20 points)
    result.details.tlsFingerprint = generateTlsFingerprint(req);
    
    // Check for unusual cipher suites
    const unusualCiphers = ['ECDHE-RSA-AES128-SHA', 'ECDHE-RSA-AES256-SHA', 'AES128-SHA', 'AES256-SHA'];
    if (tlsInfo.name && unusualCiphers.includes(tlsInfo.name)) {
        botScore += 10;
        result.reasons.push(`Unusual cipher suite: ${tlsInfo.name}`);
    }
    
    // Check for weak TLS versions
    if (tlsInfo.version && (tlsInfo.version === 'TLSv1' || tlsInfo.version === 'TLSv1.1')) {
        botScore += 10;
        result.reasons.push(`Weak TLS version: ${tlsInfo.version}`);
    }
    
    // 4. Header Inconsistencies (15 points)
    const headerChecks = {
        missingSecHeaders: !req.headers['sec-ch-ua'] && userAgent.match(/chrome|edge|opera|firefox/i),
        missingCommonHeaders: (!acceptLanguage || !req.headers['accept-encoding']) && 
                            userAgent.match(/mozilla|chrome|safari|firefox|edge/i),
        headerOrder: Object.keys(req.headers).join(',').toLowerCase() !== 
                   ['host','connection','accept','user-agent','accept-encoding','accept-language'].join(','),
        uaInconsistency: (userAgent.includes('chrome') && !accept.includes('application/signed-exchange')) ||
                        (userAgent.includes('firefox') && !accept.includes('text/html')) ||
                        (userAgent.includes('safari') && !accept.includes('application/xhtml+xml'))
    };
    
    if (headerChecks.missingSecHeaders) {
        botScore += 8;
        result.reasons.push("Missing modern browser security headers (Sec-CH-UA, Sec-Fetch-*)");
    }
    
    if (headerChecks.missingCommonHeaders) {
        botScore += 5;
        result.reasons.push("Missing common browser headers");
    }
    
    if (headerChecks.headerOrder) {
        botScore += 5;
        result.reasons.push("Non-standard header order");
    }
    
    if (headerChecks.uaInconsistency) {
        botScore += 5;
        result.reasons.push("User-Agent inconsistent with Accept headers");
    }
    
    // 5. Request Timing (12 points)
    const now = Date.now();
    const ipKey = ip.split(',')[0].trim();
    
    if (requestTimingMap.has(ipKey)) {
        const lastTiming = requestTimingMap.get(ipKey);
        const timeSinceLast = now - lastTiming.lastRequest;
        const interval = lastTiming.interval;
        
        if (interval && Math.abs(timeSinceLast - interval) < 50) {
            botScore += 12;
            result.reasons.push(`Machine-like request timing (interval: ${interval}ms ±50ms)`);
        }
        
        requestTimingMap.set(ipKey, {
            lastRequest: now,
            interval: timeSinceLast,
            count: lastTiming.count + 1
        });
    } else {
        requestTimingMap.set(ipKey, {
            lastRequest: now,
            interval: null,
            count: 1
        });
    }
    
    // 6. Human-like Indicators (-5 points)
    const humanPatterns = [
        'mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera',
        'windows', 'macintosh', 'linux', 'iphone', 'android'
    ];
    
    humanPatterns.forEach(pattern => {
        if (userAgent.includes(pattern)) {
            botScore = Math.max(0, botScore - 5);
            result.reasons.push(`Human-like pattern detected: ${pattern}`);
        }
    });
    
    // Final score calculation
    result.score = botScore;
    result.isBot = result.score >= threshold;
    result.isBlock = result.isBot;
    
    return result;
}

function generateTlsFingerprint(req) {
    if (!req.socket) return null;
    
    try {
        const tls = req.socket;
        const components = [
            tls.encrypted ? 'TLS' : 'Plain',
            typeof tls.getProtocol === 'function' ? tls.getProtocol() || 'unknown' : 'unknown',
            typeof tls.getCipher === 'function' ? tls.getCipher()?.name || 'unknown' : 'unknown',
            typeof tls.getEphemeralKeyInfo === 'function' ? tls.getEphemeralKeyInfo()?.type || 'unknown' : 'unknown'
        ];

        return crypto.createHash('md5')
            .update(components.join('-'))
            .digest('hex');
    } catch (error) {
        console.error('Error generating TLS fingerprint:', error);
        return null;
    }
}

function isKnownBot(userAgent) {
    return crawlers.some(crawler => {
        // Gunakan regex dari package untuk matching akurat
        const pattern = new RegExp(crawler.pattern, 'i');
        return pattern.test(userAgent);
    });
}

function generateTlsFingerprint(req) {
    if (!req.socket) return null;
    
    try {
        const tls = req.socket;
        const components = [
            tls.encrypted ? 'TLS' : 'Plain',
            typeof tls.getProtocol === 'function' ? tls.getProtocol() || 'unknown' : 'unknown',
            typeof tls.getCipher === 'function' ? tls.getCipher()?.name || 'unknown' : 'unknown',
            typeof tls.getEphemeralKeyInfo === 'function' ? tls.getEphemeralKeyInfo()?.type || 'unknown' : 'unknown'
        ];

        return crypto.createHash('md5')
            .update(components.join('-'))
            .digest('hex');
    } catch (error) {
        console.error('Error generating TLS fingerprint:', error);
        return null;
    }
}

// API Endpoints
app.get('/api/blocker', validateApiKey, async (req, res) => {
  try {
    const ip = req.query.ip || req.headers['x-forwarded-for'] || req.ip;
    const hostname = req.query.hostname || req.headers['host'] || '';
    const userAgent = req.query.ua || req.headers['user-agent'] || '';
    
    // Check known bots first
    if (isKnownBot(userAgent)) {
      return res.status(403).json({
        is_block: true,
        message: "Blocked: Known crawler/bot detected",
        crawler_info: crawlers.find(c => new RegExp(c.pattern, 'i').test(userAgent))
      });
    }
    
    // Create mock request object
    const startTime = Date.now();
    const mockRequest = {
      headers: {
        'user-agent': userAgent,
        'host': req.headers.host || '',
        'accept': req.headers.accept || '',
        'connection': req.headers.connection || '',
        'via': req.headers.via || '',
        'x-forwarded-for': ip,
        'referer': req.headers.referer || '',
        'cookie': req.headers.cookie || '',
        'accept-language': req.headers['accept-language'] || '',
        'sec-ch-ua': req.headers['sec-ch-ua'] || '',
        'sec-fetch-site': req.headers['sec-fetch-site'] || '',
        'sec-fetch-mode': req.headers['sec-fetch-mode'] || ''
      },
      query: req.query,
      path: req.path,
      ip: ip,
      httpVersion: req.httpVersion,
      socket: req.socket,
      connection: { remoteAddress: ip },
      timing: { start: startTime, duration: 0 }
    };
    
    // Parallel detection
    const [botDetection, vpnTorInfo, threatInfo, dataCenterInfo] = await Promise.all([
      isRequestFromBot(mockRequest),
      detectVpnOrTor(ip),
      enhancedDetection(ip, hostname),
      detectDataCenter(ip)
    ]);
    
    // Add detection info to the mock request for scoring
    mockRequest.vpnTorInfo = vpnTorInfo;
    mockRequest.datacenterInfo = dataCenterInfo;
    
    // Re-run bot detection with the additional info
    const finalBotDetection = isRequestFromBot(mockRequest);
    
    // Calculate processing time
    mockRequest.timing.duration = Date.now() - startTime;
    
    // Enhanced response with all detection info
    const response = {
      is_bot: finalBotDetection.isBot,
      is_block: finalBotDetection.isBlock || threatInfo.threats_detected,
      detection_score: finalBotDetection.score,
      detection_reasons: finalBotDetection.reasons,
      threats: {
        is_blacklisted_ip: threatInfo.is_blacklisted_ip,
        is_blacklisted_host: threatInfo.is_blacklisted_host,
        is_threat_url: threatInfo.is_threat_url,
        is_vpn: vpnTorInfo.is_vpn,
        is_tor: vpnTorInfo.is_tor,
        is_proxy: vpnTorInfo.is_proxy,
        is_datacenter: dataCenterInfo.is_datacenter
      },
      ip_details: {
        ip: ip,
        isp: vpnTorInfo.details?.isp || dataCenterInfo.details?.isp,
        org: vpnTorInfo.details?.org || dataCenterInfo.details?.org,
        asn: vpnTorInfo.details?.asn || dataCenterInfo.details?.asn,
        type: dataCenterInfo.details?.type
      },
      fingerprinting: {
        tls: finalBotDetection.details.tlsFingerprint,
        http_version: finalBotDetection.details.httpVersion,
        timing: mockRequest.timing
      },
      user_agent: userAgent,
      timestamp: new Date().toISOString()
    };
    
    // If blocking, send 403
    if (response.is_block) {
      return res.status(403).json({
        ...response,
        error: 'Forbidden',
        message: 'Threat detected and blocked'
      });
    }
    
    res.json(response);
    
  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: error.message
    });
  }
});

// IP info endpoint
app.get('/api/ip-info', validateApiKey, async (req, res) => {
  try {
    const ip = req.query.ip || req.headers['x-forwarded-for'] || req.ip;
    const vpnTorInfo = await detectVpnOrTor(ip);
    
    res.json({
      ip: ip,
      is_vpn: vpnTorInfo.is_vpn,
      is_tor: vpnTorInfo.is_tor,
      is_proxy: vpnTorInfo.is_proxy,
      detection_method: vpnTorInfo.method,
      details: vpnTorInfo.details,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error fetching IP info:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: error.message
    });
  }
});

app.get('/api/threat-check', validateApiKey, async (req, res) => {
  try {
    const ip = req.query.ip || req.headers['x-forwarded-for'] || req.ip;
    const hostname = req.query.hostname || req.headers['host'] || '';
    
    const threatInfo = await enhancedDetection(ip, hostname);
    
    res.json({
      ip: ip,
      hostname: hostname,
      threats_detected: threatInfo.threats_detected,
      details: {
        blacklisted_ip: threatInfo.is_blacklisted_ip,
        blacklisted_host: threatInfo.is_blacklisted_host,
        threat_url: threatInfo.is_threat_url,
        vpn: threatInfo.is_vpn,
        tor: threatInfo.is_tor,
        proxy: threatInfo.is_proxy
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error checking threats:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: error.message
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  try {
    // Check all critical components
    const healthChecks = {
      server: {
        status: 'healthy',
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
        loadAvg: process.cpuUsage()
      },
      blocklists: {
        torNodes: {
          loaded: torExitNodes.size > 0,
          count: torExitNodes.size
        },
        vpnRanges: {
          loaded: vpnIpRanges.size > 0,
          count: vpnIpRanges.size
        },
        maliciousIPs: {
          loaded: maliciousIps.size > 0,
          count: maliciousIps.size
        },
        hostnames: {
          loaded: hostnameBlacklist.size > 0,
          count: hostnameBlacklist.size
        },
        threatURLs: {
          loaded: threatUrls.size > 0,
          count: threatUrls.size
        },
        allListsLoaded: torExitNodes.size > 0 && 
                      vpnIpRanges.size > 0 && 
                      maliciousIps.size > 0 && 
                      hostnameBlacklist.size > 0 && 
                      threatUrls.size > 0
      },
      externalServices: {
        ipwhois: {
          status: 'untested', // Will be tested below
          url: IPWHOIS_API
        }
      },
      requestTracking: {
        activeIPs: requestTimingMap.size
      },
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        timestamp: new Date().toISOString()
      }
    };

    // Test external services
    Promise.all([
      fetch(IPWHOIS_API).then(() => {
        healthChecks.externalServices.ipwhois.status = 'healthy';
      }).catch(() => {
        healthChecks.externalServices.ipwhois.status = 'unhealthy';
      }),
      fetch(TOR_EXIT_NODES_URL).then(() => {
        healthChecks.externalServices.torList = { status: 'reachable' };
      }).catch(() => {
        healthChecks.externalServices.torList = { status: 'unreachable' };
      })
    ]).then(() => {
      // Determine overall status
      const allServicesHealthy = 
        healthChecks.externalServices.ipwhois.status === 'healthy' &&
        healthChecks.blocklists.allListsLoaded;

      healthChecks.status = allServicesHealthy ? 'healthy' : 'degraded';
      healthChecks.message = allServicesHealthy 
        ? 'All systems operational' 
        : 'Some services may be degraded';

      // Add response time
      healthChecks.responseTime = `${Date.now() - res.locals.startTime}ms`;

      res.status(allServicesHealthy ? 200 : 503).json(healthChecks);
    });

    // Track start time for response time calculation
    res.locals.startTime = Date.now();

  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({
      status: 'unhealthy',
      error: 'Health check failed',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API keys loaded: ${API_KEYS.size}`);
});