// Manifest V3-compliant background script for CyberSentinel

chrome.runtime.onInstalled.addListener(() => {
  console.log("✅ CyberSentinel background running");

  // Update declarative net request rules on install
  updateDNRRules();
});

// Function to update DNR rules dynamically
async function updateDNRRules() {
  try {
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    const ruleIds = rules.map(rule => rule.id);

    if (ruleIds.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: ruleIds
      });
    }

    // Add dynamic rules for known malicious domains
    const newRules = blockedDomains.map((domain, index) => ({
      id: index + 1000, // Start from 1000 to avoid conflicts with static rules
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: `*://*${domain}/*`,
        resourceTypes: ["main_frame", "sub_frame"]
      }
    }));

    if (newRules.length > 0) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        addRules: newRules
      });
    }
  } catch (error) {
    console.error("Error updating DNR rules:", error);
  }
}

// prevention of threat 
const blockedDomains = ['malicious.com', 'phishing-site.com'];
let logs = [];

//keyword based detection
const keywordSets = [
  ['malicious', 'phishing', 'attack', 'virus'],
  ['trojan', 'exploit', 'ransomware', 'worm'],
  ['spyware', 'adware', 'rootkit', 'botnet'],
  ['keylogger', 'backdoor', 'zero-day', 'sql injection'],
  ['xss', 'csrf', 'ddos', 'brute force'],
  ['spoofing', 'scam', 'payload', 'threat'],
  ['malware', 'hacker', 'breach', 'leak'],
  ['credential', 'session', 'cookie', 'redirect'],
  ['fake', 'clone', 'impersonate', 'steal'],
  ['danger', 'risk', 'compromise', 'unauthorized']
];
let keywordIndex = 0;
let filteredKeywords = keywordSets[0];

function rotateKeywords() {
  keywordIndex = (keywordIndex + 1) % keywordSets.length;
  filteredKeywords = keywordSets[keywordIndex]
    .slice()
    .sort(() => Math.random() - 0.5); // shuffle order
}

// Helper: Log threat detection
function logThreat(message) {
  rotateKeywords(); // Rotate keywords for every new log/alert
  const logEntry = `[${new Date().toLocaleTimeString()}]  ${message}`;
  logs.push(logEntry);
  if (logs.length > 20) logs.shift();
}

//  Check domains with APIs
async function checkDomainSafety(url) {
  try {
    rotateKeywords();
    // Check blockedDomains first (synchronous)
    if (blockedDomains.some(domain => url.hostname.includes(domain))) {
      logThreat(`Blocked: ${url.hostname} (in blocklist)`);
      broadcastThreatAlert('Domain in blocklist', url.href);
      return { blocked: true, reason: 'Domain in blocklist' };
    }

    // Check Google Safe Browsing
    const safeBrowsingResult = await checkWithGoogleSafeBrowsing(url.href);
    if (safeBrowsingResult) {
      logThreat(`Blocked by Google Safe Browsing: ${url.href}`);
      broadcastThreatAlert('Flagged by Google Safe Browsing', url.href);
      return { blocked: true, reason: 'Flagged by Google Safe Browsing' };
    }

    // Check AbuseIPDB
    const abuseIPDBResult = await checkWithAbuseIPDB(url.hostname);
    if (abuseIPDBResult) {
      logThreat(`Blocked by AbuseIPDB: ${url.hostname}`);
      broadcastThreatAlert('Flagged by AbuseIPDB', url.href);
      return { blocked: true, reason: 'Flagged by AbuseIPDB' };
    }

    return { blocked: false };
  } catch (e) {
    console.error('Error checking domain safety:', e);
    return { blocked: false };
  }
}

//  Handle downloads
chrome.downloads.onCreated.addListener(function(downloadItem) {
  try {
    const url = new URL(downloadItem.url);
    // Immediate check
    if (blockedDomains.some(domain => url.hostname.includes(domain))) {
      chrome.downloads.cancel(downloadItem.id);
      logThreat(`Blocked download from: ${url.hostname}`);
      return;
    }

    // Async checks
    checkDomainSafety(url).then(result => {
      if (result.blocked) {
        chrome.downloads.cancel(downloadItem.id);
        logThreat(`Cancelled download from ${url.hostname}: ${result.reason}`);
      }
    });
  } catch (e) { console.error(e); }
});

//  Log visited websites
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) {
    const logEntry = `[${new Date().toLocaleTimeString()}] Visited: ${details.url}`;
    logs.push(logEntry);
    if (logs.length > 20) logs.shift();
  }
});

// Handle messages from popup and content scripts
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'CLOSE_TAB' && sender.tab?.id) {
    chrome.tabs.remove(sender.tab.id);
    logThreat(`Closed tab due to high-severity threat: ${sender.tab.url}`);
    sendResponse({ success: true });
  }
  else if (msg.type === 'SEND_ALERT') {
    logThreat(msg.reason || 'Manual alert');
    sendResponse({ success: true });
  }
  else if (msg.type === 'GET_DATA') {
    sendResponse({
      logs: logs.slice().reverse(),
      keywords: filteredKeywords
    });
  }
  return true;
});

//  AbuseIPDB API integration for IP/domain reputation
async function checkWithAbuseIPDB(ipOrDomain) {
  const apiKey = 'cc32320ab72c3bc44ff636f27a481beb868d26a04c7f4d85feaa6dc5fdde0139a0947b06ec46d1f2';
  const apiUrl = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ipOrDomain)}&maxAgeInDays=90`;
  try {
    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      }
    });
    if (!response.ok) return false;
    const data = await response.json();
    // AbuseIPDB returns a 'data.abuseConfidenceScore' (0-100)
    if (data && data.data && data.data.abuseConfidenceScore >= 50) {
      console.log('Blocked by AbuseIPDB:', ipOrDomain, 'Score:', data.data.abuseConfidenceScore);
      return true;
    }
  } catch (e) {
    console.error('AbuseIPDB API error:', e);
    return false;
  }
  return false;
}

//  Google Safe Browsing API integration for domain checks
async function checkWithGoogleSafeBrowsing(urlToCheck) {
  const apiKey = 'AIzaSyA0aDP_G1ADk82n79_UbWeF2vvlrlYLAEY';
  const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const body = {
    client: {
      clientId: "cybersentinal-extension",
      clientVersion: "1.0"
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [
        { url: urlToCheck }
      ]
    }
  };
  try {
    const response = await fetch(apiUrl, {
      method: 'POST',
      body: JSON.stringify(body),
      headers: { 'Content-Type': 'application/json' }
    });
    if (!response.ok) return false;
    const data = await response.json();
    return !!(data && data.matches && data.matches.length > 0);
  } catch (e) {
    console.error('Safe Browsing API error:', e);
    return false;
  }
}

//  Broadcast alerts to content scripts and popup
function broadcastThreatAlert(reason, url) {
  chrome.tabs.query({}, function(tabs) {
    tabs.forEach(tab => {
      chrome.tabs.sendMessage(tab.id, {
        type: 'THREAT_ALERT',
        reason,
        url
      });
    });
  });
}
