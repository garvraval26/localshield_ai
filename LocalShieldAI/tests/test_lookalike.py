from detector.lookalike import find_lookalike


def test_flags_typos_and_lookalikes():
    for host in ["gooogle.cooom", "google.cooom", "gooogle.org", "gooogle.com", "g00gle.com",
                 "paypa1.com", "rnicrosoft.com", "paytm-kyc-update.xyz", "sbi-secure-login.com",
                 "paytm.com.verify-now.xyz", "paytm.verify-now.xyz", "hdfcbank.co", "amaz0n.in",
                 "faceb00k.com", "gogle.com", "amazonn.net", "faceboook.co", "paytm.xyz",
                 "aitrel.com", "biannce.com", "fedex.cooom", "dhl-parcel-track.top",
                 "binance-login.com", "citib4nk.com", "yahooo.com"]:
        assert find_lookalike(host), host


def test_real_domains_not_flagged():
    for host in ["google.com", "www.google.com", "mail.google.com", "amazon.in", "amazon.co.in",
                 "example.com", "github.com", "wikipedia.org", "bbc.co.uk", "stackoverflow.com",
                 "sbi.co.in", "onlinesbi.sbi", "npci.org.in", "python.org", "openai.com",
                 "paytm.com", "pay.paytm.com", "microsoft.com", "mozilla.org", "medium.com",
                 "paypal.com", "google.org", "netflix.net", "amazing.com", "apply.org",
                 "googleapis.com", "amazonaws.com", "twitch.tv", "uber.com", "zoom.us",
                 "airtel.in", "yahoo.com", "dhl.de", "coinbase.com"]:
        assert find_lookalike(host) is None, host