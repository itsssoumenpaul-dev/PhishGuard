"""Reference data. Extend freely: these lists are intentionally plain Python."""

# brand token -> official registered domains
BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "google.co.in", "gmail.com", "googleapis.com", "gstatic.com", "youtube.com", "goo.gl"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "office365.com", "azure.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com", "amazon.de"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "dropbox": ["dropbox.com"],
    "github": ["github.com", "githubusercontent.com"],
    "adobe": ["adobe.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "paytm": ["paytm.com", "paytmbank.com"],
    "phonepe": ["phonepe.com"],
    "gpay": ["pay.google.com"],
    "npci": ["npci.org.in"],
    "bhim": ["bhimupi.org.in"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank.in"],
    "hdfc": ["hdfcbank.com", "hdfc.com", "hdfcsec.com"],
    "hdfcbank": ["hdfcbank.com"],
    "icici": ["icicibank.com", "icicidirect.com", "icicilombard.com"],
    "icicibank": ["icicibank.com"],
    "axisbank": ["axisbank.com"],
    "kotak": ["kotak.com", "kotak811.com"],
    "pnb": ["pnbindia.in", "netpnb.com"],
    "irctc": ["irctc.co.in"],
    "uidai": ["uidai.gov.in"],
    "aadhaar": ["uidai.gov.in"],
    "incometax": ["incometax.gov.in", "incometaxindiaefiling.gov.in"],
    "epfo": ["epfindia.gov.in"],
    "digilocker": ["digilocker.gov.in"],
    "naukri": ["naukri.com"],
    "indeed": ["indeed.com", "indeed.co.in"],
    "flipkart": ["flipkart.com"],
    "swiggy": ["swiggy.com"],
    "zomato": ["zomato.com"],
    "jio": ["jio.com", "ril.com"],
    "airtel": ["airtel.in", "airtel.com"],
    "tcs": ["tcs.com"],
    "infosys": ["infosys.com"],
    "wipro": ["wipro.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citi.com", "citibank.com"],
    "hsbc": ["hsbc.com", "hsbc.co.in", "hsbc.co.uk"],
}

# also treat each official domain's own name (e.g. "microsoftonline", "onlinesbi") as a brand token
for _t, _doms in list(BRANDS.items()):
    for _d in _doms:
        _n = _d.split(".")[0]
        if len(_n) >= 5 and _n not in BRANDS:
            BRANDS[_n] = _doms

# registered-domain suffixes made of two labels (small built-in subset of the PSL)
MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "ac.in", "gov.in", "nic.in",
    "res.in", "edu.in", "firm.in", "gen.in", "ind.in", "com.au", "net.au", "org.au", "co.jp", "com.br",
    "co.za", "com.cn", "com.sg", "co.nz", "com.mx", "com.tr", "co.kr", "com.hk", "bank.in",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "country", "work", "support", "zip", "mov",
    "loan", "men", "icu", "buzz", "rest", "cyou", "cfd", "sbs", "monster", "online", "site", "live",
    "link", "vip", "fit", "bid", "download", "stream", "party", "review",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy",
    "shorturl.at", "tiny.cc", "rebrand.ly", "s.id", "lnkd.in", "t.ly", "bl.ink",
}

# free hosting / site builders / form services that phishing kits commonly abuse
FREE_HOSTING = {
    "weebly.com", "wixsite.com", "blogspot.com", "github.io", "pages.dev", "netlify.app", "vercel.app",
    "web.app", "firebaseapp.com", "glitch.me", "herokuapp.com", "000webhostapp.com", "forms.gle",
    "typeform.com", "jotform.com", "sites.google.com", "notion.site", "carrd.co", "webflow.io",
    "godaddysites.com", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "workers.dev", "r2.dev",
    "duckdns.org", "no-ip.org", "ddns.net", "hopto.org", "infinityfreeapp.com", "rf.gd",
}
# official brand domains that also host arbitrary user content: no trust bonus
USER_CONTENT_HOSTS = {"docs.google.com", "sites.google.com", "drive.google.com", "forms.gle",
                      "storage.googleapis.com", "github.io", "githubusercontent.com", "amazonaws.com",
                      "azurewebsites.net", "dropbox.com", "onedrive.live.com", "1drv.ms"}

URL_KEYWORDS = [
    "login", "signin", "log-in", "sign-in", "verify", "verification", "secure", "security", "account",
    "update", "confirm", "wallet", "kyc", "otp", "banking", "billing", "invoice", "password", "recover",
    "unlock", "suspend", "limited", "refund", "reward", "prize", "claim", "bonus", "support", "helpdesk",
    "payment", "upi", "authenticate", "validate",
]

# visually-confusable characters -> ascii
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ο": "o", "ν": "v", "ι": "i", "α": "a", "ρ": "p", "τ": "t",
    "ƅ": "b", "ɑ": "a", "ǝ": "e", "ı": "i", "ⅼ": "l", "ο": "o", "օ": "o", "ս": "u", "ɩ": "i",
}

# text patterns for page content themes
TEXT_THEMES = {
    "urgency": [r"account (?:has been |will be |is )?(?:suspended|locked|limited|blocked|disabled)",
                r"within (?:24|48) hours", r"immediate(?:ly)? (?:action|verification)", r"unusual (?:activity|sign[- ]?in)",
                r"verify your (?:identity|account|details)", r"your (?:account|card|kyc) (?:is )?(?:expired|expiring|pending)"],
    "credentials": [r"\benter (?:your )?(?:otp|pin|password|cvv)\b", r"\b(?:card number|cvv|cvc|expiry)\b",
                    r"\b(?:aadhaar|aadhar|pan card|net ?banking|upi pin|mpin)\b", r"\bone[- ]time password\b"],
    "payment_scam": [r"\bprocessing fee\b", r"\bregistration fee\b", r"\bsecurity deposit\b", r"\bpay (?:rs\.?|₹|inr)\s?\d",
                     r"\bscan (?:the )?qr\b", r"\bcollect request\b", r"\brefund (?:is )?(?:pending|initiated|failed)\b",
                     r"\bclaim your (?:prize|reward|refund|cashback)\b", r"\blottery\b|\bcongratulations,? you(?:'|’)?ve? (?:won|been selected)"],
    "job_scam": [r"\bwork from home\b", r"\bearn (?:rs\.?|₹|\$)?\s?\d[\d,]*\s?(?:per|/)\s?(?:day|week|hour)\b",
                 r"\bjoin (?:our )?(?:telegram|whatsapp)\b", r"\boffer letter\b", r"\bno experience (?:needed|required)\b",
                 r"\blimited (?:vacancies|seats)\b"],
}

# end-of-life / old software branches (maintain this table; matched against Server/X-Powered-By/script URLs)
EOL_RULES = [
    ("php", r"PHP/(\d+)\.(\d+)", lambda a, b: (a, b) < (8, 2), "PHP branches below 8.2 no longer receive security fixes"),
    ("apache", r"Apache/(\d+)\.(\d+)", lambda a, b: (a, b) < (2, 4), "Apache httpd 2.2 and older are end-of-life"),
    ("nginx", r"nginx/(\d+)\.(\d+)", lambda a, b: (a, b) < (1, 24), "nginx releases older than 1.24 are unsupported"),
    ("iis", r"Microsoft-IIS/(\d+)\.(\d+)", lambda a, b: a < 10, "IIS older than 10 runs on unsupported Windows Server"),
    ("openssl", r"OpenSSL/(\d+)\.(\d+)", lambda a, b: (a, b) < (3, 0), "OpenSSL 1.x is end-of-life"),
    ("asp.net", r"ASP\.NET[^\d]*(\d+)\.(\d+)", lambda a, b: a < 4, "ASP.NET 2.x/3.x are unsupported"),
]
