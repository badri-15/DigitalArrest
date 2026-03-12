/**
 * DigitalArmour — i18n (English + Hindi)
 * Usage: add data-i18n="key" to any element whose textContent should be translated.
 *        For placeholders: data-i18n-ph="key"
 * The active language is stored in localStorage under 'da_lang'.
 */
const DA_TRANSLATIONS = {
  en: {
    /* ── HEADER ── */
    'nav.helpline':        '📞 1930',
    'nav.lang-toggle':     'हिं',

    /* ── INDEX — HERO ── */
    'hero.eyebrow':        '🇮🇳 India Cybercrime Prevention',
    'hero.title-line1':    'Got a suspicious call?',
    'hero.title-line2':    "Report it. We'll detect it.",
    'hero.subtitle':       "Fill in what happened on the call — who called, what they claimed, what they wanted. Our engine analyses it and tells you if it's a scam.",

    /* ── INDEX — SCANNER CARD ── */
    'scan.card-title':     'Paste Message or Describe the Call',
    'scan.field-hint':     'Paste the exact SMS / WhatsApp message you received, or type what the caller said in your own words.',
    'scan.placeholder':    "e.g. 'Dear Customer, your SBI KYC has expired…'\n\nOr: 'A person called claiming to be an ED officer…'",
    'scan.btn':            '🔍 Scan Now',
    'scan.bar':            'Analysing your report across 5 scam categories…',

    /* ── INDEX — DEMO ── */
    'demo.title':          '🧪 Demo Test Cases',

    /* ── INDEX — HISTORY ── */
    'hist.title':          '🕓 Your Previous Scans',
    'hist.clear':          'Clear',
    'hist.empty':          'No scans yet — your results will appear here.',

    /* ── INDEX — ANALYTICS ── */
    'analytics.title':     '📊 Live Analytics',
    'analytics.badge':     'TODAY',
    'kpi.detected':        'Scams Detected',
    'kpi.money':           'Money Protected',
    'kpi.users':           'Users Warned',
    'kpi.top':             'Most: Digital Arrest',
    'bd.title':            'Scam Type Breakdown',
    'lf.title':            'Recent Detections',

    /* ── INDEX — HELPLINE CARD ── */
    'hl.title':            '🆘 Need Help Now?',
    'hl.call-main':        'Call 1930',
    'hl.call-sub':         'Cyber Crime Helpline · Free · 24×7',
    'hl.web-main':         'Report at cybercrime.gov.in',
    'hl.web-sub':          'Official National Cyber Crime Portal',
    'hl.cert-main':        'CERT-In Portal',
    'hl.cert-sub':         'cert-in.org.in · Cyber Security Incidents',
    'hl.note':             'Free official government services. Never pay anyone claiming to be from a helpline.',

    /* ── INDEX — FOOTER ── */
    'footer.text':         'Built for Hackathon 2025 · Helpline:',

    /* ── SCAM DETAIL — HEADER ── */
    'detail.back':         '← Back to Scanner',
    'detail.breadcrumb1':  'DigitalArmour',
    'detail.breadcrumb2':  'Scam Guide',

    /* ── SCAM DETAIL — FACTS ── */
    'detail.fact-threat':  'Threat Level',
    'detail.fact-kw':      'Detection Keywords',
    'detail.fact-steps':   'Protective Steps',
    'detail.fact-phrases': 'phrases',
    'detail.fact-actions': 'actions',

    /* ── SCAM DETAIL — CTA ── */
    'detail.cta-strong':   'Got a suspicious message related to this?',
    'detail.cta-span':     'Paste it in the scanner — our engine analyses it in seconds.',
    'detail.cta-btn':      '🔍 Scan a Message',

    /* ── SCAM DETAIL — SECTIONS ── */
    'detail.kw-lbl':       'Warning Signals',
    'detail.kw-ttl':       'Trigger Phrases & Threat Weights',
    'detail.kw-hint':      'Each phrase is weighted <strong>1–10</strong> based on how exclusively it appears in scam messages. Weight 10 = almost never used in legitimate communication.',
    'detail.eg-lbl':       'Real Scam Example',
    'detail.eg-msg-lbl':   'Typical scam message',
    'detail.eg-warn':      '⚠ This is an example for awareness only — do not respond to messages like this.',
    'detail.act-lbl':      'Immediate Actions',
    'detail.act-ttl':      'What You Must Do Right Now',
    'detail.rpt-lbl':      'Official Government Channels',
    'detail.rpt-ttl':      "Report This Scam — It's Free",
    'detail.hl-call-main': 'Call 1930',
    'detail.hl-call-sub':  'National Cyber Crime Helpline · Free · 24×7',
    'detail.hl-web-main':  'cybercrime.gov.in',
    'detail.hl-web-sub':   'Official National Cyber Crime Reporting Portal',
    'detail.hl-cert-main': 'CERT-In Portal',
    'detail.hl-cert-sub':  'cert-in.org.in · Cyber Security Incident Response',
    'detail.hl-note':      'All services are free and operated by the Government of India. Never pay anyone claiming to be from a helpline.',
    'detail.sev-suffix':   'SEVERITY',
    'detail.country-tag':  'India Cyber Crime — Active Scam Type',

    /* ── SHARED FOOTER ── */
    'footer.back':         '← Back to DigitalArmour Scanner',
    'footer.helpline':     'Helpline:',
  },

  hi: {
    /* ── HEADER ── */
    'nav.helpline':        '📞 1930',
    'nav.lang-toggle':     'EN',

    /* ── INDEX — HERO ── */
    'hero.eyebrow':        '🇮🇳 भारत साइबर अपराध रोकथाम',
    'hero.title-line1':    'संदिग्ध कॉल आई?',
    'hero.title-line2':    'रिपोर्ट करें। हम पहचानेंगे।',
    'hero.subtitle':       'कॉल में क्या हुआ — किसने फोन किया, क्या कहा, क्या माँगा — सब लिखें। हमारा इंजन विश्लेषण करके बताएगा कि यह धोखाधड़ी है या नहीं।',

    /* ── INDEX — SCANNER CARD ── */
    'scan.card-title':     'संदेश पेस्ट करें या कॉल का विवरण लिखें',
    'scan.field-hint':     'प्राप्त SMS / WhatsApp संदेश सीधे पेस्ट करें, या जो कॉलर ने कहा वो अपने शब्दों में लिखें।',
    'scan.placeholder':    "उदा. 'प्रिय ग्राहक, आपका SBI KYC समाप्त हो गया है…'\n\नया: 'एक व्यक्ति ने ED अधिकारी बनकर फोन किया…'",
    'scan.btn':            '🔍 अभी स्कैन करें',
    'scan.bar':            '5 श्रेणियों में आपकी रिपोर्ट का विश्लेषण हो रहा है…',

    /* ── INDEX — DEMO ── */
    'demo.title':          '🧪 डेमो टेस्ट केस',

    /* ── INDEX — HISTORY ── */
    'hist.title':          '🕓 आपके पिछले स्कैन',
    'hist.clear':          'मिटाएं',
    'hist.empty':          'अभी कोई स्कैन नहीं — परिणाम यहाँ दिखेंगे।',

    /* ── INDEX — ANALYTICS ── */
    'analytics.title':     '📊 लाइव आँकड़े',
    'analytics.badge':     'आज',
    'kpi.detected':        'धोखाधड़ी पकड़ी गई',
    'kpi.money':           'धन सुरक्षित',
    'kpi.users':           'उपयोगकर्ता सतर्क',
    'kpi.top':             'सबसे अधिक: डिजिटल गिरफ्तारी',
    'bd.title':            'धोखाधड़ी प्रकार विवरण',
    'lf.title':            'हालिया पहचान',

    /* ── INDEX — HELPLINE CARD ── */
    'hl.title':            '🆘 अभी मदद चाहिए?',
    'hl.call-main':        '1930 पर कॉल करें',
    'hl.call-sub':         'साइबर क्राइम हेल्पलाइन · निःशुल्क · 24×7',
    'hl.web-main':         'cybercrime.gov.in पर रिपोर्ट करें',
    'hl.web-sub':          'राष्ट्रीय साइबर क्राइम रिपोर्टिंग पोर्टल',
    'hl.cert-main':        'CERT-In पोर्टल',
    'hl.cert-sub':         'cert-in.org.in · साइबर सुरक्षा घटनाएं',
    'hl.note':             'सभी सेवाएं निःशुल्क और सरकारी हैं। कोई भी हेल्पलाइन के नाम पर पैसे माँगे तो न दें।',

    /* ── INDEX — FOOTER ── */
    'footer.text':         'Hackathon 2025 के लिए निर्मित · हेल्पलाइन:',

    /* ── SCAM DETAIL — HEADER ── */
    'detail.back':         '← स्कैनर पर वापस जाएं',
    'detail.breadcrumb1':  'DigitalArmour',
    'detail.breadcrumb2':  'धोखाधड़ी मार्गदर्शिका',

    /* ── SCAM DETAIL — FACTS ── */
    'detail.fact-threat':  'खतरे का स्तर',
    'detail.fact-kw':      'पहचान कीवर्ड',
    'detail.fact-steps':   'सुरक्षात्मक कदम',
    'detail.fact-phrases': 'वाक्यांश',
    'detail.fact-actions': 'कार्य',

    /* ── SCAM DETAIL — CTA ── */
    'detail.cta-strong':   'इससे संबंधित कोई संदिग्ध संदेश मिला?',
    'detail.cta-span':     'स्कैनर में पेस्ट करें — हमारा इंजन कुछ ही सेकंड में जाँच करेगा।',
    'detail.cta-btn':      '🔍 संदेश स्कैन करें',

    /* ── SCAM DETAIL — SECTIONS ── */
    'detail.kw-lbl':       'चेतावनी संकेत',
    'detail.kw-ttl':       'ट्रिगर वाक्यांश और खतरे का भार',
    'detail.kw-hint':      'प्रत्येक वाक्यांश को <strong>1–10</strong> भार दिया गया है। भार 10 = वैध संचार में लगभग कभी उपयोग नहीं होता।',
    'detail.eg-lbl':       'असली धोखाधड़ी का उदाहरण',
    'detail.eg-msg-lbl':   'सामान्य धोखाधड़ी संदेश',
    'detail.eg-warn':      '⚠ यह केवल जागरूकता के लिए है — ऐसे संदेशों का जवाब न दें।',
    'detail.act-lbl':      'तत्काल कार्रवाई',
    'detail.act-ttl':      'अभी यह करें',
    'detail.rpt-lbl':      'आधिकारिक सरकारी चैनल',
    'detail.rpt-ttl':      'यह धोखाधड़ी रिपोर्ट करें — निःशुल्क',
    'detail.hl-call-main': '1930 पर कॉल करें',
    'detail.hl-call-sub':  'राष्ट्रीय साइबर क्राइम हेल्पलाइन · निःशुल्क · 24×7',
    'detail.hl-web-main':  'cybercrime.gov.in',
    'detail.hl-web-sub':   'राष्ट्रीय साइबर क्राइम रिपोर्टिंग पोर्टल',
    'detail.hl-cert-main': 'CERT-In पोर्टल',
    'detail.hl-cert-sub':  'cert-in.org.in · साइबर सुरक्षा घटना प्रतिक्रिया',
    'detail.hl-note':      'सभी सेवाएं भारत सरकार द्वारा निःशुल्क संचालित हैं। हेल्पलाइन के नाम पर कोई भी पैसे माँगे तो न दें।',
    'detail.sev-suffix':   'गंभीरता',
    'detail.country-tag':  'भारत साइबर क्राइम — सक्रिय धोखाधड़ी प्रकार',

    /* ── SHARED FOOTER ── */
    'footer.back':         '← DigitalArmour स्कैनर पर वापस',
    'footer.helpline':     'हेल्पलाइन:',
  }
};

const DA_I18N_LANG_KEY = 'da_lang';

function daGetLang() {
  return localStorage.getItem(DA_I18N_LANG_KEY) || 'en';
}

function daApplyLang(lang) {
  const T = DA_TRANSLATIONS[lang] || DA_TRANSLATIONS.en;
  document.documentElement.lang = lang === 'hi' ? 'hi' : 'en';

  // Text content
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.dataset.i18n;
    if (T[key] !== undefined) el.innerHTML = T[key];
  });

  // Placeholders
  document.querySelectorAll('[data-i18n-ph]').forEach(el => {
    const key = el.dataset.i18nPh;
    if (T[key] !== undefined) el.placeholder = T[key];
  });

  // Store
  localStorage.setItem(DA_I18N_LANG_KEY, lang);
}

function daToggleLang() {
  const next = daGetLang() === 'en' ? 'hi' : 'en';
  daApplyLang(next);
}

// Auto-apply on load
document.addEventListener('DOMContentLoaded', () => daApplyLang(daGetLang()));
