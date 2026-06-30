const PERSIST_DAYS = 365;
const IMPORTANT_DOMAINS = [
  'google.com', 'gmail.com', 'accounts.google.com', 'myaccount.google.com',
  'youtube.com', 'googleusercontent.com', 'gstatic.com',
  'ticketmaster.com', 'livenation.com',
  'seatgeek.com', 'axs.com',
  'microsoft.com', 'live.com', 'outlook.com', 'login.microsoftonline.com',
  'facebook.com', 'instagram.com',
  'twitter.com', 'x.com',
  'amazon.com',
  'apple.com', 'icloud.com'
];

function domainMatches(cookieDomain, pattern) {
  const d = cookieDomain.startsWith('.') ? cookieDomain.substring(1) : cookieDomain;
  return d === pattern || d.endsWith('.' + pattern);
}

function isImportantDomain(domain) {
  return IMPORTANT_DOMAINS.some(p => domainMatches(domain, p));
}

async function persistSessionCookies() {
  const allCookies = await chrome.cookies.getAll({});
  const futureDate = Date.now() / 1000 + PERSIST_DAYS * 86400;
  let converted = 0;

  for (const cookie of allCookies) {
    if (cookie.session && isImportantDomain(cookie.domain)) {
      const url = (cookie.secure ? 'https://' : 'http://') +
        (cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain) +
        cookie.path;
      try {
        await chrome.cookies.set({
          url: url,
          name: cookie.name,
          value: cookie.value,
          domain: cookie.domain,
          path: cookie.path,
          secure: cookie.secure,
          httpOnly: cookie.httpOnly,
          sameSite: cookie.sameSite || 'unspecified',
          expirationDate: futureDate
        });
        converted++;
      } catch (e) {}
    }
  }

  if (converted > 0) {
    console.log('[PX Session Keeper] Persisted ' + converted + ' session cookies');
  }
}

chrome.alarms.create('persist-cookies', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'persist-cookies') {
    persistSessionCookies();
  }
});

chrome.cookies.onChanged.addListener((changeInfo) => {
  if (!changeInfo.removed && changeInfo.cookie.session && isImportantDomain(changeInfo.cookie.domain)) {
    const cookie = changeInfo.cookie;
    const url = (cookie.secure ? 'https://' : 'http://') +
      (cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain) +
      cookie.path;
    const futureDate = Date.now() / 1000 + PERSIST_DAYS * 86400;
    chrome.cookies.set({
      url: url,
      name: cookie.name,
      value: cookie.value,
      domain: cookie.domain,
      path: cookie.path,
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite || 'unspecified',
      expirationDate: futureDate
    }).catch(() => {});
  }
});

persistSessionCookies();
console.log('[PX Session Keeper] Active - monitoring session cookies');
