// content.js
console.log('Content script loaded.');

// --- Threat Detection Functions ---

// Detects suspicious SQL injection patterns in the URL query string
function checkURLForSQLInjection() {
    const sqlPatterns = [
        /('|%27)\s*(or|and)\s*('|%27)?\d+=\d+/i, 
        /('|%27)\s*--/i,
        /('|%27);/i,
        /(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)/i, // SQL keywords
        /(\bDROP\b|\bTABLE\b|\bDATABASE\b)/i
    ];
    const query = window.location.search;
    for (const pattern of sqlPatterns) {
        if (pattern.test(query)) {
            return {
                detected: true,
                pattern: pattern.toString(),
                message: "Potential SQL Injection pattern detected in URL."
            };
        }
    }
    return { detected: false };
}

// Import configuration
const config = window.PhishingConfig || {};

// Detects phishing based on domain and page content
function detectPhishingPage() {
    const { suspiciousKeywords = [], suspiciousDomains = [] } = config;
    let details = [];
    let threatType = '';
      
    let detected = false;
    if (suspiciousDomains.some(domain => window.location.hostname.includes(domain))) {
        detected = true;
        threatType = 'Suspicious Domain';
        details.push('Suspicious domain detected: ' + window.location.hostname);
    }
    
    const bodyText = document.body.innerText.toLowerCase();
    const foundKeywords = [];
    suspiciousKeywords.forEach(keyword => {
        if (bodyText.includes(keyword)) {
            detected = true;
            foundKeywords.push(keyword);
            details.push('Suspicious keyword found: ' + keyword);
        }
    });
    
    if (foundKeywords.length > 0) {
        threatType = threatType ? threatType + ' & Suspicious Keywords' : 'Suspicious Keywords';
    }
    
    if (document.querySelector('input[type="password"]')) {
        detected = true;
        threatType = threatType ? threatType + ' & Password Field' : 'Password Field';
        details.push('Password field detected on this page.');
    }
    
    // Show alert if threat is detected
    if (detected) {
        const alertMessage = ` SECURITY ALERT \n\n` +
                          `Threat Type: ${threatType}\n\n` +
                          `Details:\n- ${details.join('\n- ')}`;
        alert(alertMessage);
    }
    
    return { detected, details };
}

// --- Run phishing detection on load and on DOM changes ---
detectPhishingPage();
const phishingObserver = new MutationObserver(() => {
    detectPhishingPage();
});
phishingObserver.observe(document.body, { childList: true, subtree: true });

// Checks for insecure cookies (no Secure/HttpOnly flags)
function checkInsecureCookies() {
    let insecureCookies = [];
    document.cookie.split(';').forEach(cookie => {
        if (cookie && !cookie.toLowerCase().includes('secure') && !cookie.toLowerCase().includes('httponly')) {
            insecureCookies.push(cookie.trim());
        }
    });
    if (insecureCookies.length > 0) {
        return {
            detected: true,
            details: ['Insecure cookies detected: ' + insecureCookies.join(', ')]
        };
    }
    return { detected: false };
}

// Call a cybersecurity API for domain reputation (placeholder)
async function checkDomainReputationAPI(domain) {
    
    const apiUrl = `https://phishtank.com/check-domain?domain=${encodeURIComponent(domain)}`;
    try {
        const response = await fetch(apiUrl);
        if (!response.ok) return null;
        const data = await response.json();
        // Assume API returns { malicious: true/false, reason: "..." }
        if (data.malicious) {
            return { detected: true, details: [`API: Domain flagged as malicious. Reason: ${data.reason}`] };
        }
    } catch (e) { /* ignore errors for now */ }
    return { detected: false };
}

//  Main Threat Detection Runner 
(async function runAllThreatChecks() {
    let threatDetected = false;
    let threatDetails = [];

    // SQL Injection
    const sqlResult = checkURLForSQLInjection();
    if (sqlResult.detected) {
        threatDetected = true;
        threatDetails.push(sqlResult.message + ' Pattern: ' + sqlResult.pattern);
    }

    // Phishing
    const phishingResult = detectPhishingPage();
    if (phishingResult.detected) {
        threatDetected = true;
        threatDetails = threatDetails.concat(phishingResult.details);
    }

    // Insecure Cookies
    const cookieResult = checkInsecureCookies();
    if (cookieResult.detected) {
        threatDetected = true;
        threatDetails = threatDetails.concat(cookieResult.details);
    }

    // Domain Reputation API (async)
    const apiResult = await checkDomainReputationAPI(window.location.hostname);
    if (apiResult && apiResult.detected) {
        threatDetected = true;
        threatDetails = threatDetails.concat(apiResult.details);
    }

    if (threatDetected) {
        chrome.storage.local.set({
            threatAlert: {
                url: window.location.href,
                details: threatDetails,
                timestamp: Date.now()
            }
        });
    }
})();

//Threat prevention 
const blockedDomains = ['malicious.com', 'phishing-site.com'];

// 3. Prevent suspicious form submissions
function blockSuspiciousForms() {
  document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
      try {
        const action = form.action || window.location.href;
        if (blockedDomains.some(domain => action.includes(domain))) {
          e.preventDefault();
          alert('Form submission blocked: suspicious destination.');
          console.log('Blocked form submission to:', action);
        }
      } catch (err) { console.error(err); }
    });
  });
}
blockSuspiciousForms();
const observer = new MutationObserver(blockSuspiciousForms);
observer.observe(document.body, { childList: true, subtree: true });

//  Intercept and block malicious fetch() and XMLHttpRequest calls
(function() {
  const originalFetch = window.fetch;
  window.fetch = function(...args) { 
    try {
      if (args[0] && blockedDomains.some(domain => args[0].includes(domain))) {
        console.log('Blocked fetch to:', args[0]);
        return Promise.reject(new Error('Blocked by extension'));
      }
    } catch (e) { console.error(e); }
    return originalFetch.apply(this, args);
  };

  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    try {
      if (blockedDomains.some(domain => url.includes(domain))) {
        console.log('Blocked XHR to:', url);
        throw new Error('Blocked by extension');
      }
    } catch (e) { console.error(e); }
    return originalOpen.call(this, method, url, ...rest);
  };
})();

//  Stop execution of dangerous scripts (like eval, atob, execCommand)
(function() {
  window.eval = function() {
    console.log('Blocked eval()');
    throw new Error('eval() is disabled by extension');
  };
  window.atob = function() {
    console.log('Blocked atob()');
    throw new Error('atob() is disabled by extension');
  };
  document.execCommand = function() {
    console.log('Blocked execCommand()');
    throw new Error('execCommand() is disabled by extension');
  };
})();

function autoCloseTabIfHighThreat() {
  if (window.location.hostname.includes('malicious.com')) {
    chrome.runtime.sendMessage({ type: 'CLOSE_TAB' });
  }
}
autoCloseTabIfHighThreat();

// SQL Injection API Integration 
const checkedURLs = new Set();

async function checkURLForSQLInjectionAPI(url) {
    try {
        const response = await fetch('http://localhost:5001/check-sqli', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await response.json();
        return data;
    } catch (e) {
        console.error('Error checking SQLi:', e);
        return { detected: false };
    }
}

async function automatedSQLInjectionCheck() {
    const linkElements = Array.from(document.querySelectorAll('a[href]'));
    const formElements = Array.from(document.querySelectorAll('form[action]'));

    // Process links
    for (const link of linkElements) {
        const fullUrl = new URL(link.href, window.location.origin).toString();
        if (checkedURLs.has(fullUrl)) continue;
        checkedURLs.add(fullUrl);
        const result = await checkURLForSQLInjectionAPI(fullUrl);
        if (result.detected) {
            console.warn('SQLi found in link:', fullUrl, result.details);
            link.style.border = '2px solid red';
        }
    }

    // Process forms
    for (const form of formElements) {
        const fullUrl = new URL(form.action, window.location.origin).toString();
        if (checkedURLs.has(fullUrl)) continue;
        checkedURLs.add(fullUrl);
        const result = await checkURLForSQLInjectionAPI(fullUrl);
        if (result.detected) {
            console.warn('SQLi found in form action:', fullUrl, result.details);
            form.style.border = '2px solid orange';
        }
    }
}

window.addEventListener('DOMContentLoaded', automatedSQLInjectionCheck);
const sqliObserver = new MutationObserver(() => {
    automatedSQLInjectionCheck();
});
sqliObserver.observe(document.body, { childList: true, subtree: true });