"""
domain_allowlist.py
Allowlist + lookalike checker for the phishing detector.

pip install tldextract
Verdicts: "safe" | "malicious" | "review"
  safe      -> exact allowlisted domain, skip the ML detector
  malicious -> hard rule hit (invalid TLD, typosquat, brand-in-subdomain)
  review    -> send to your ML detector, pass `flags` to Llama as context
"""
import ipaddress
import re
from urllib.parse import urlparse

import tldextract

# offline: uses the suffix list bundled with the package
_extract = tldextract.TLDExtract(suffix_list_urls=())

# ----------------------------------------------------------------------------
# 1) GLOBAL
# ----------------------------------------------------------------------------
GLOBAL = """
google.com youtube.com gmail.com bing.com yahoo.com duckduckgo.com baidu.com yandex.com ecosia.org brave.com
msn.com live.com outlook.com office.com microsoft.com microsoftonline.com aol.com proton.me protonmail.com
icloud.com apple.com zoho.com mail.com gmx.com fastmail.com tutanota.com
facebook.com instagram.com whatsapp.com messenger.com twitter.com x.com linkedin.com pinterest.com reddit.com
tumblr.com snapchat.com tiktok.com telegram.org discord.com signal.org quora.com medium.com threads.net
twitch.tv vimeo.com flickr.com meetup.com nextdoor.com weibo.com vk.com line.me wechat.com slack.com zoom.us
skype.com webex.com gotomeeting.com mastodon.social bsky.app goodreads.com strava.com deviantart.com
behance.net dribbble.com
amazon.com ebay.com aliexpress.com alibaba.com walmart.com target.com bestbuy.com etsy.com shopify.com
costco.com homedepot.com lowes.com ikea.com wayfair.com zalando.com shein.com temu.com rakuten.com
mercadolibre.com newegg.com overstock.com macys.com nordstrom.com kohls.com zara.com hm.com nike.com
adidas.com puma.com uniqlo.com sephora.com ulta.com samsung.com sony.com lg.com dell.com hp.com lenovo.com
asus.com acer.com logitech.com bose.com gopro.com canon.com nikon.com xiaomi.com huawei.com oppo.com
vivo.com oneplus.com nothing.tech motorola.com nokia.com realme.com garmin.com fitbit.com
netflix.com spotify.com hulu.com disneyplus.com hbomax.com max.com primevideo.com paramountplus.com
peacocktv.com crunchyroll.com soundcloud.com deezer.com tidal.com pandora.com imdb.com rottentomatoes.com
letterboxd.com dailymotion.com plex.tv roku.com audible.com bandcamp.com shazam.com
paypal.com stripe.com visa.com mastercard.com americanexpress.com chase.com bankofamerica.com wellsfargo.com
citi.com capitalone.com usbank.com pnc.com td.com hsbc.com barclays.co.uk lloydsbank.com natwest.com
santander.com ing.com bnpparibas.com ubs.com goldmansachs.com jpmorgan.com morganstanley.com schwab.com
fidelity.com vanguard.com etrade.com robinhood.com wise.com revolut.com klarna.com venmo.com cash.app
zellepay.com westernunion.com moneygram.com payoneer.com skrill.com neteller.com squareup.com adyen.com
worldpay.com checkout.com affirm.com sofi.com intuit.com turbotax.com quickbooks.com bloomberg.com
reuters.com ft.com wsj.com marketwatch.com investing.com tradingview.com morningstar.com nasdaq.com
nyse.com cnbc.com forbes.com fortune.com businessinsider.com
bbc.com bbc.co.uk cnn.com nytimes.com theguardian.com washingtonpost.com foxnews.com nbcnews.com
cbsnews.com usatoday.com apnews.com aljazeera.com dw.com france24.com economist.com time.com newsweek.com
politico.com npr.org pbs.org huffpost.com buzzfeed.com vice.com vox.com theverge.com techcrunch.com
wired.com arstechnica.com engadget.com cnet.com zdnet.com gizmodo.com mashable.com theatlantic.com
newyorker.com independent.co.uk telegraph.co.uk dailymail.co.uk mirror.co.uk thesun.co.uk sky.com
lemonde.fr spiegel.de elpais.com corriere.it asahi.com nikkei.com scmp.com straitstimes.com smh.com.au
abc.net.au theglobeandmail.com cbc.ca nzherald.co.nz
booking.com airbnb.com expedia.com tripadvisor.com agoda.com kayak.com skyscanner.com hotels.com
trivago.com vrbo.com uber.com lyft.com grab.com delta.com united.com aa.com southwest.com jetblue.com
emirates.com qatarairways.com etihad.com lufthansa.com britishairways.com airfrance.com klm.com
singaporeair.com cathaypacific.com qantas.com ryanair.com easyjet.com turkishairlines.com marriott.com
hilton.com hyatt.com ihg.com accor.com fedex.com ups.com dhl.com usps.com maersk.com
github.com gitlab.com bitbucket.org stackoverflow.com stackexchange.com npmjs.com pypi.org python.org
nodejs.org rust-lang.org golang.org go.dev java.com oracle.com docker.com kubernetes.io cloudflare.com
digitalocean.com heroku.com vercel.com netlify.com azure.com ibm.com redhat.com ubuntu.com debian.org
mozilla.org firefox.com opera.com chromium.org jetbrains.com visualstudio.com atlassian.com notion.so
figma.com canva.com adobe.com dropbox.com box.com onedrive.com mega.nz wetransfer.com trello.com
asana.com monday.com airtable.com hubspot.com salesforce.com zendesk.com mailchimp.com sendgrid.com
twilio.com okta.com auth0.com datadog.com splunk.com elastic.co mongodb.com postgresql.org mysql.com
redis.io openai.com anthropic.com claude.ai huggingface.co kaggle.com nvidia.com intel.com amd.com arm.com
qualcomm.com cisco.com juniper.net paloaltonetworks.com fortinet.com symantec.com norton.com mcafee.com
kaspersky.com avast.com avg.com bitdefender.com malwarebytes.com eset.com nordvpn.com expressvpn.com
1password.com lastpass.com bitwarden.com godaddy.com namecheap.com wordpress.com wordpress.org wix.com
squarespace.com weebly.com substack.com
wikipedia.org wikimedia.org britannica.com khanacademy.org coursera.org udemy.com edx.org udacity.com
duolingo.com quizlet.com chegg.com brainly.com scribd.com academia.edu researchgate.net arxiv.org
nature.com science.org sciencedirect.com springer.com wiley.com jstor.org
who.int mayoclinic.org webmd.com healthline.com
steampowered.com steamcommunity.com epicgames.com ea.com ubisoft.com blizzard.com battle.net riotgames.com
leagueoflegends.com minecraft.net roblox.com playstation.com xbox.com nintendo.com gog.com itch.io
humblebundle.com rockstargames.com activision.com supercell.com mojang.com unity.com unrealengine.com
archive.org w3.org ietf.org icann.org iana.org apache.org gnu.org linuxfoundation.org kernel.org
openstreetmap.org mapbox.com waze.com weather.com accuweather.com timeanddate.com speedtest.net fast.com
gravatar.com unsplash.com pexels.com pixabay.com shutterstock.com gettyimages.com istockphoto.com
flaticon.com freepik.com fontawesome.com jquery.com bootstrapcdn.com akamai.com fastly.com statista.com
glassdoor.com indeed.com monster.com ziprecruiter.com upwork.com fiverr.com freelancer.com toptal.com
craigslist.org yelp.com zillow.com realtor.com redfin.com trulia.com autotrader.com cars.com carvana.com
tesla.com ford.com gm.com toyota.com honda.com bmw.com mercedes-benz.com audi.com volkswagen.com
hyundai.com kia.com nissan.com volvocars.com porsche.com ferrari.com lamborghini.com
mcdonalds.com starbucks.com kfc.com subway.com dominos.com pizzahut.com burgerking.com doordash.com
ubereats.com grubhub.com instacart.com deliveroo.com just-eat.com chipotle.com
coca-cola.com pepsi.com nestle.com unilever.com pg.com loreal.com danone.com mondelezinternational.com
kraftheinz.com
att.com verizon.com t-mobile.com comcast.com xfinity.com spectrum.com vodafone.com orange.com telefonica.com
telekom.de bt.com rogers.com bell.ca telus.com singtel.com optus.com.au telstra.com.au
geico.com progressive.com statefarm.com allstate.com aetna.com cigna.com unitedhealthcare.com
anthem.com kp.org humana.com
docusign.com hellosign.com calendly.com typeform.com surveymonkey.com grammarly.com evernote.com
lucidchart.com miro.com loom.com clickup.com basecamp.com pipedrive.com intercom.com segment.com
mixpanel.com amplitude.com hotjar.com sentry.io newrelic.com pagerduty.com snowflake.com databricks.com
tableau.com powerbi.com looker.com sap.com workday.com servicenow.com vmware.com citrix.com
dell.com.au bitly.com tinyurl.com
cloudinary.com imgur.com giphy.com tenor.com gfycat.com pastebin.com gist.github.com
nytimes.co wsj.net
"""

# ----------------------------------------------------------------------------
# 2) INDIA
# ----------------------------------------------------------------------------
INDIA = """
sbi.co.in onlinesbi.sbi onlinesbi.com hdfcbank.com icicibank.com axisbank.com kotak.com pnbindia.in
bankofbaroda.in canarabank.com unionbankofindia.co.in bankofindia.co.in indianbank.in
centralbankofindia.co.in iob.in ucobank.com bankofmaharashtra.in punjabandsindbank.co.in
idfcfirstbank.com indusind.com yesbank.in federalbank.co.in rblbank.com bandhanbank.com
southindianbank.com karurvysyabank.com cityunionbank.com dcbbank.com csb.co.in tmb.in jkbank.com
aubank.in equitasbank.com ujjivansfb.in utkarsh.bank esafbank.com suryodaybank.com janabank.com
idbibank.in dhanbank.com nainitalbank.co.in paytmbank.com airtelbank.com ippbonline.com hsbc.co.in
sc.com citibank.co.in dbs.com
paytm.com phonepe.com bhimupi.org.in npci.org.in razorpay.com cashfree.com payu.in payumoney.com
ccavenue.com billdesk.com instamojo.com mobikwik.com freecharge.in amazonpay.in juspay.in cred.club
sliceit.com jupiter.money fi.money navi.com groww.in zerodha.com upstox.com angelone.in angelbroking.com
5paisa.com icicidirect.com hdfcsec.com kotaksecurities.com sharekhan.com motilaloswal.com iifl.com
nseindia.com bseindia.com cdslindia.com nsdl.co.in camsonline.com kfintech.com mfcentral.com
amfiindia.com moneycontrol.com screener.in tickertape.in smallcase.com policybazaar.com
insurancedekho.com acko.com godigit.com licindia.in hdfclife.com iciciprulife.com sbilife.co.in
maxlifeinsurance.com bajajallianz.com tataaig.com starhealth.in careinsurance.com nivabupa.com
hdfcergo.com icicilombard.com newindia.co.in uiic.co.in orientalinsurance.org.in bajajfinserv.in
bajajfinance.in tatacapital.com muthootfinance.com manappuram.com hdfc.com lichousing.com
pnbhousing.com canfinhomes.com aavas.in homefirstindia.com cibil.com experian.in equifax.co.in
crifhighmark.com bankbazaar.com paisabazaar.com moneyview.in kreditbee.in lendingkart.com
zestmoney.com earlysalary.com olamoney.com tin-nsdl.com utiitsl.com protean-tp.com
amazon.in flipkart.com myntra.com ajio.com nykaa.com meesho.com snapdeal.com tatacliq.com jiomart.com
bigbasket.com blinkit.com zeptonow.com swiggy.com zomato.com dunzo.com licious.in freshtohome.com
firstcry.com lenskart.com purplle.com tirabeauty.com mamaearth.in boat-lifestyle.com gonoise.com
fastrack.in titan.co.in tanishq.co.in caratlane.com bluestone.com malabargoldanddiamonds.com
kalyanjewellers.net joyalukkas.com pcjeweller.com croma.com reliancedigital.in vijaysales.com
poorvika.com sangeethamobiles.com pepperfry.com urbanladder.com hometown.in fabindia.com westside.com
pantaloons.com lifestylestores.com shoppersstop.com maxfashion.in bata.in relaxofootwear.com
woodlandworldwide.com libas.in biba.in wforwoman.com zivame.com bewakoof.com thesouledstore.com
snitch.co.in nnnow.com limeroad.com shopclues.com indiamart.com tradeindia.com justdial.com
sulekha.com olx.in quikr.com cardekho.com cars24.com spinny.com carwale.com bikewale.com
zigwheels.com droom.in 1mg.com pharmeasy.in netmeds.com apollopharmacy.in apollo247.com practo.com
medplusmart.com healthifyme.com cult.fit curefit.com tata1mg.com
irctc.co.in makemytrip.com goibibo.com yatra.com cleartrip.com easemytrip.com ixigo.com redbus.in
abhibus.com confirmtkt.com trainman.in railyatri.in oyorooms.com oyo.com treebo.com fabhotels.com
zostel.com thomascook.in sotc.in veenaworld.com kesari.in airindia.com airindia.in goindigo.in
spicejet.com akasaair.com airindiaexpress.com flyvistara.com allianceair.com flybig.in ola.com
olacabs.com rapido.bike merucabs.com blablacar.in zoomcar.com revv.co.in drivezy.com yulu.bike
bounce.bike ihmcl.com delhimetrorail.com bmrc.co.in delhiairport.com bengaluruairport.com hyderabad.aero
jio.com reliancejio.com airtel.in myvi.in vodafoneidea.com bsnl.co.in mtnl.in tataplay.com tatasky.com
dishtv.in d2h.com sundirect.in actcorp.in hathway.com excitel.com
timesofindia.indiatimes.com indiatimes.com hindustantimes.com thehindu.com indianexpress.com ndtv.com
indiatoday.in news18.com republicworld.com aajtak.in abplive.com zeenews.india.com zeebiz.com
firstpost.com thewire.in scroll.in theprint.in thequint.com livemint.com business-standard.com
financialexpress.com deccanherald.com deccanchronicle.com telegraphindia.com tribuneindia.com
newindianexpress.com dnaindia.com mid-day.com freepressjournal.in outlookindia.com theweek.in
businesstoday.in forbesindia.com inc42.com yourstory.com entrackr.com medianama.com bhaskar.com
jagran.com amarujala.com livehindustan.com patrika.com navbharattimes.com jansatta.com lokmat.com
loksatta.com eenadu.net sakshi.com mathrubhumi.com manoramaonline.com dinamalar.com dailythanthi.com
dinamani.com vikatan.com anandabazar.com prabhatkhabar.com indiatvnews.com wionews.com
hotstar.com jiocinema.com sonyliv.com zee5.com altbalaji.com voot.com mxplayer.in sunnxt.com aha.video
hoichoi.tv jiosaavn.com gaana.com wynk.in bookmyshow.com insider.in district.in dream11.com mpl.live
winzo.com my11circle.com cricbuzz.com espncricinfo.com iplt20.com bcci.tv prokabaddi.com
indiansuperleague.com
byjus.com unacademy.com vedantu.com pw.live toppr.com extramarks.com embibe.com testbook.com adda247.com
byjusexamprep.com careers360.com shiksha.com collegedunia.com collegedekho.com naukri.com foundit.in
monsterindia.com shine.com timesjobs.com apna.co workindia.in internshala.com hirist.tech iimjobs.com
instahyre.com cutshort.io wellfound.com upgrad.com simplilearn.com mygreatlearning.com scaler.com
codingninjas.com geeksforgeeks.org w3schools.com tutorialspoint.com javatpoint.com leetcode.com
hackerrank.com hackerearth.com codechef.com codeforces.com nptel.ac.in
tcs.com infosys.com wipro.com hcltech.com techmahindra.com ltimindtree.com mphasis.com cognizant.com
capgemini.com accenture.com zoho.in freshworks.com freshdesk.com nasscom.in tatamotors.com tata.com
tatasteel.com tataconsumer.com tatapower.com tajhotels.com ril.com adani.com adaniports.com mahindra.com
marutisuzuki.com nexaexperience.com heromotocorp.com bajajauto.com tvsmotor.com royalenfield.com
hondacarindia.com mgmotor.co.in skoda-auto.co.in volkswagen.co.in toyotabharat.com asianpaints.com
hul.co.in itcportal.com nestle.in britannia.co.in amul.com dabur.com patanjaliayurved.net marico.com
godrej.com godrejcp.com havells.com bajajelectricals.com crompton.co.in voltas.com bluestarindia.com
whirlpoolindia.com larsentoubro.com lntecc.com ongcindia.com iocl.com bharatpetroleum.in hindustanpetroleum.com
gailonline.com ntpc.co.in powergrid.in coalindia.in sail.co.in hindalco.com vedantalimited.com jsw.in
jindalsteel.com ultratechcement.com ambujacement.com acclimited.com shreecement.com grasim.com
sunpharma.com drreddys.com cipla.com lupin.com zyduslife.com biocon.com divislabs.com apollohospitals.com
fortishealthcare.com maxhealthcare.in manipalhospitals.com narayanahealth.org medanta.org aiims.edu
mygov.in digilocker.gov.in cowin.gov.in
indigoair.com jobsora.in magicbricks.com 99acres.com housing.com nobroker.in nestaway.com commonfloor.com
squareyards.com proptiger.com makaan.com urbanclap.com urbancompany.com housejoy.in quickerala.com
dineout.co.in eatsure.com faasos.com behrouzbiryani.com dominos.co.in pizzahut.co.in kfcindia.com
mcdonaldsindia.com burgerking.in haldirams.com bikanervala.com chaayos.com
airtelxstream.in jiofiber.com tataneu.com neupass.tataneu.com tatadigital.com
shaadi.com jeevansathi.com bharatmatrimony.com matrimony.com
sarkariresult.com freejobalert.com rojgarresult.com
pib.gov.in
"""

# ----------------------------------------------------------------------------
# 3) MIXED (crypto, intl orgs, security, infra, misc)
# ----------------------------------------------------------------------------
MIXED = """
binance.com binance.us coinbase.com kraken.com bitfinex.com bitstamp.net gemini.com kucoin.com okx.com
bybit.com gate.io huobi.com htx.com bitget.com mexc.com crypto.com bitmart.com lbank.com phemex.com
deribit.com bitflyer.com upbit.com bithumb.com coincheck.com bitso.com luno.com wazirx.com coindcx.com
zebpay.com mudrex.com giottus.com bitbns.com unocoin.com coinswitch.co
bitcoin.org ethereum.org solana.com cardano.org polkadot.network avax.network polygon.technology chain.link
uniswap.org aave.com compound.finance makerdao.com curve.fi sushi.com pancakeswap.finance 1inch.io
dydx.exchange lido.fi rocketpool.net ens.domains opensea.io blur.io rarible.com looksrare.org magiceden.io
metamask.io trustwallet.com phantom.app ledger.com trezor.io exodus.com atomicwallet.io myetherwallet.com
rainbow.me walletconnect.com safe.global argent.xyz blockchain.com blockchair.com etherscan.io bscscan.com
polygonscan.com solscan.io tronscan.org coinmarketcap.com coingecko.com coindesk.com cointelegraph.com
theblock.co decrypt.co messari.io glassnode.com dune.com defillama.com dexscreener.com dextools.io
tether.to circle.com paxos.com ripple.com stellar.org tron.network litecoin.org dogecoin.com
getmonero.org z.cash filecoin.io arweave.org near.org cosmos.network algorand.com tezos.com hedera.com
aptoslabs.com sui.io arbitrum.io optimism.io base.org zksync.io starknet.io scroll.io blast.io
chainalysis.com elliptic.co bitpay.com coinpayments.net moonpay.com ramp.network transak.com banxa.com
changelly.com nexo.com grayscale.com coinshares.com bitwiseinvestments.com ark-invest.com
un.org worldbank.org imf.org wto.org oecd.org europa.eu nato.int interpol.int icrc.org unicef.org
unesco.org unhcr.org fao.org ilo.org itu.int wipo.int redcross.org amnesty.org hrw.org greenpeace.org
wwf.org oxfam.org savethechildren.org msf.org gatesfoundation.org eff.org fsf.org
bundesregierung.de bund.de elysee.fr service-public.fr gouvernement.fr canada.ca govt.nz
mit.edu harvard.edu stanford.edu ox.ac.uk cam.ac.uk ethz.ch epfl.ch tsinghua.edu.cn u-tokyo.ac.jp
nus.edu.sg
cloudflare-dns.com one.one.one.one dns.google opendns.com quad9.net letsencrypt.org digicert.com
sectigo.com globalsign.com entrust.com verisign.com godaddy.net networksolutions.com hover.com
gandi.net porkbun.com dynadot.com name.com ionos.com hostinger.com bluehost.com hostgator.com
siteground.com dreamhost.com linode.com vultr.com ovhcloud.com hetzner.com scaleway.com rackspace.com
cloud.google.com aws.amazon.com console.aws.amazon.com
crowdstrike.com sentinelone.com trendmicro.com sophos.com checkpoint.com zscaler.com proofpoint.com
mimecast.com rapid7.com tenable.com qualys.com virustotal.com haveibeenpwned.com urlscan.io
shodan.io owasp.org cve.org mitre.org sans.org cisecurity.org first.org
tailscale.com wireguard.com openvpn.net protonvpn.com mullvad.net surfshark.com cyberghostvpn.com
privateinternetaccess.com torproject.org
fedex.com.au aramex.com royalmail.com canadapost-postescanada.ca auspost.com.au deutschepost.de
laposte.fr correos.es poste.it postnl.nl japanpost.jp indiapost.gov.in
alipay.com tenpay.com qq.com taobao.com tmall.com jd.com pinduoduo.com bilibili.com douyin.com
meituan.com didiglobal.com baiduyun.com sina.com.cn sohu.com 163.com naver.com kakao.com daum.net
rakuten.co.jp yahoo.co.jp mercari.com lycorp.co.jp dmm.com nicovideo.jp
mail.ru ok.ru sberbank.ru tinkoff.ru yandex.ru kaspersky.ru
globo.com uol.com.br magazineluiza.com.br americanas.com.br nubank.com.br itau.com.br bradesco.com.br
bancodobrasil.com.br santander.com.br caixa.gov.br
bbva.com bbva.es caixabank.es sabadell.com unicredit.it intesasanpaolo.com commerzbank.com
sparkasse.de postbank.de rabobank.com abnamro.com credit-agricole.fr societegenerale.com
dnb.no nordea.com swedbank.com seb.se danskebank.com handelsbanken.com
commbank.com.au anz.com.au westpac.com.au nab.com.au rbc.com bmo.com cibc.com scotiabank.com
dbs.com.sg ocbc.com uob.com.sg maybank.com cimb.com bangkokbank.com kasikornbank.com
standardbank.co.za fnb.co.za absa.co.za nedbank.co.za capitecbank.co.za
emiratesnbd.com adcb.com qnb.com alrajhibank.com.sa
safaricom.co.ke mpesa.com mtn.com airtel.com vodacom.co.za
flutterwave.com paystack.com opay.ng kuda.com
ticketmaster.com stubhub.com eventbrite.com seatgeek.com livenation.com fandango.com
patreon.com kickstarter.com indiegogo.com gofundme.com ko-fi.com buymeacoffee.com onlyfans.com
change.org avaaz.org
chatgpt.com gemini.google.com perplexity.ai midjourney.com stability.ai mistral.ai cohere.com
replicate.com runwayml.com elevenlabs.io poe.com character.ai
nasa.gov noaa.gov cdc.gov nih.gov fda.gov irs.gov ssa.gov usa.gov
walgreens.com cvs.com rite-aid.com goodrx.com zocdoc.com teladoc.com
pfizer.com moderna.com jnj.com novartis.com roche.com astrazeneca.com gsk.com sanofi.com merck.com
bayer.com abbvie.com lilly.com bms.com
siemens.com bosch.com basf.com philips.com abb.com schneider-electric.com ge.com honeywell.com 3m.com
caterpillar.com deere.com boeing.com airbus.com lockheedmartin.com rtx.com northropgrumman.com
shell.com bp.com exxonmobil.com chevron.com totalenergies.com aramco.com
berkshirehathaway.com blackrock.com statestreet.com pimco.com
ancestry.com 23andme.com myheritage.com
sciencemag.org cell.com thelancet.com nejm.org bmj.com plos.org pubmed.ncbi.nlm.nih.gov
"""


# extra mixed batch
MORE_MIXED = """
bitrue.com poloniex.com bitvavo.com coinex.com whitebit.com bingx.com bitkub.com indodax.com
tokocrypto.com coinmena.com coinjar.com swyftx.com independentreserve.com coinspot.com btcmarkets.net
newton.co ndax.io shakepay.com bitbuy.ca paxful.com
balancer.fi yearn.fi convexfinance.com synthetix.io frax.finance ethena.fi eigenlayer.xyz pendle.finance
gmx.io jup.ag raydium.io orca.so marinade.finance jito.network tensor.trade
alchemy.com infura.io moralis.io quicknode.com thegraph.com consensys.io chainlist.org revoke.cash
debank.com zapper.xyz zerion.io ethereum.foundation
iso.org ieee.org acm.org cern.ch nationalgeographic.com smithsonianmag.com britishmuseum.org louvre.fr
metmuseum.org ted.com
aldi.com lidl.com carrefour.com tesco.com sainsburys.co.uk asda.com argos.co.uk johnlewis.com
marksandspencer.com boots.com currys.co.uk
paysafe.com bluesnap.com braintreepayments.com authorize.net paddle.com gumroad.com lemonsqueezy.com
cloudways.com kinsta.com wpengine.com render.com fly.io railway.app supabase.com firebase.google.com
planetscale.com neon.tech cockroachlabs.com confluent.io hashicorp.com terraform.io ansible.com
puppet.com chef.io grafana.com prometheus.io jenkins.io circleci.com travis-ci.com sonarsource.com
snyk.io postman.com swagger.io insomnia.rest
zara.com.au primark.com asos.com boohoo.com next.co.uk very.co.uk debenhams.com
"""

# ----------------------------------------------------------------------------
# TRUST BY SUFFIX: nobody can register under these without verification,
# so any domain ending here is treated as safe (no need to list each one).
# ----------------------------------------------------------------------------
TRUSTED_SUFFIXES = {
    "gov", "mil", "edu", "int",
    "gov.in", "nic.in", "ac.in", "edu.in", "res.in", "mil.in",
    "gov.uk", "ac.uk", "nhs.uk", "police.uk",
    "gov.au", "edu.au", "gov.sg", "edu.sg", "gc.ca", "gouv.fr",
    "gov.za", "ac.za", "gov.br", "edu.br", "go.jp", "ac.jp",
    "gov.cn", "edu.cn", "europa.eu",
}

# Allowlisted domains where *subdomains* are user-controlled -> never auto-safe
# (the bare domain / www is still fine)
SHARED_HOSTS = {
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle",
    "storage.googleapis.com", "script.google.com", "gist.github.com",
    "wordpress.com", "medium.com", "substack.com", "tumblr.com", "weebly.com",
    "itch.io", "dropbox.com", "box.com", "notion.so", "airtable.com",
    "typeform.com", "mega.nz", "wetransfer.com", "onedrive.com",
    "cloud.google.com", "console.aws.amazon.com",
}

# ----------------------------------------------------------------------------
_RE = re.compile(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?\.[a-z0-9\-\.]+$")


def _load(blob):
    out = set()
    for d in blob.split():
        d = d.strip().lower()
        if _RE.match(d):
            out.add(d)
    return out


GLOBAL_SET, INDIA_SET, MIXED_SET = _load(GLOBAL), _load(INDIA), _load(MIXED + MORE_MIXED)
ALLOWLIST = GLOBAL_SET | INDIA_SET | MIXED_SET

# registered-domain allowlist (so "m.facebook.com" and "facebook.com" both match)
_REGISTERED = {}
for _d in ALLOWLIST:
    _e = _extract(_d)
    if _e.suffix:
        _REGISTERED[f"{_e.domain}.{_e.suffix}"] = _d
_BRANDS = {}  # label -> registered domain, e.g. "google" -> "google.com"
for _reg in _REGISTERED:
    _BRANDS.setdefault(_reg.split(".")[0], _reg)


# ----------------------------------------------------------------------------
def levenshtein(a, b):
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_HOMOGLYPH = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


def normalize(label):
    return label.lower().translate(_HOMOGLYPH).replace("rn", "m").replace("vv", "w")


def check_url(url):
    """Returns {"verdict": safe|malicious|review, "reason": str, "flags": [..]}"""
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    host = (urlparse(url).hostname or "").rstrip(".").lower()
    flags = []
    if not host:
        return {"verdict": "malicious", "reason": "no host", "flags": flags}

    # IP address hosts: no domain to trust
    try:
        ipaddress.ip_address(host)
        return {"verdict": "review", "reason": "IP address host", "flags": ["ip_host"]}
    except ValueError:
        pass

    # punycode / IDN
    if any(lbl.startswith("xn--") for lbl in host.split(".")):
        flags.append("punycode_idn")
        try:
            flags.append("decoded=" + host.encode().decode("idna"))
        except Exception:
            pass

    ext = _extract(host)

    # 1. invalid TLD (.innn, .cmo ...)
    if not ext.suffix:
        return {"verdict": "malicious", "reason": f"invalid TLD in '{host}'", "flags": flags}

    registered = f"{ext.domain}.{ext.suffix}"

    # 2. trusted suffix (gov.in, nic.in, .gov, .edu ...)
    if ext.suffix in TRUSTED_SUFFIXES and not flags:
        return {"verdict": "safe", "reason": f"trusted suffix .{ext.suffix}", "flags": flags}

    # 3. exact registered-domain match
    if registered in _REGISTERED and not flags:
        for sh in SHARED_HOSTS:
            if sh == registered:       # bare domain is fine, its subdomains are user-controlled
                bad = host.endswith("." + sh) and host != "www." + sh
            else:                      # the shared host itself (docs.google.com) and below
                bad = host == sh or host.endswith("." + sh)
            if bad:
                return {"verdict": "review", "reason": f"user-content host {host}",
                        "flags": ["user_content_host"]}
        return {"verdict": "safe", "reason": f"allowlisted ({registered})", "flags": flags}

    label = normalize(ext.domain)

    # fake official suffix in subdomain: uidai.gov.in.fake.com
    sub = "." + ext.subdomain.lower() + "."
    for sfx in TRUSTED_SUFFIXES:
        if "." in sfx and f".{sfx}." in sub:
            return {"verdict": "malicious", "reason": f"fake '.{sfx}' inside subdomain of {registered}",
                    "flags": flags}

    for brand, good in _BRANDS.items():
        if len(brand) < 5:           # too short for fuzzy matching -> too many false positives
            continue

        # 4. brand in subdomain of someone else's domain: google.com.evil.com
        if len(brand) >= 6 and brand in ext.subdomain.replace("-", "").lower():
            return {"verdict": "malicious", "reason": f"'{brand}' used in subdomain of {registered}",
                    "flags": flags}

        # 5a. homoglyph: paypa1.com, amaz0n.in (digits/lookalikes normalise to the brand)
        if label == brand and ext.domain.lower() != brand:
            return {"verdict": "malicious", "reason": f"homoglyph lookalike of {good}", "flags": flags}

        # 5. typosquat: goggle.in, paypa1.com, amaz0n.in
        if label != brand:
            maxd = 1 if len(brand) < 8 else 2
            if abs(len(label) - len(brand)) <= maxd and levenshtein(label, brand) <= maxd:
                return {"verdict": "malicious", "reason": f"lookalike of {good}", "flags": flags}
        else:
            # 6. same brand name but a different TLD (google.xyz)
            flags.append(f"brand_{brand}_on_different_tld")
            break

        # 7. brand inside a longer label: google-login.com, sbi-kyc-update.in
        if len(brand) >= 6 and brand in ext.domain.lower():
            flags.append(f"contains_brand_{brand}")

    # 8. unknown -> your ML detector decides
    return {"verdict": "review", "reason": "not in allowlist", "flags": flags}


if __name__ == "__main__":
    print(f"global={len(GLOBAL_SET)} india={len(INDIA_SET)} mixed={len(MIXED_SET)} "
          f"total={len(ALLOWLIST)}")
    tests = ["google.com", "https://mail.google.com/x", "goggle.innn", "goggle.in", "google.com.evil.com",
             "paypa1.com", "sbi-kyc-update.in", "onlinesbi.sbi", "incometax.gov.in", "amaz0n.in",
             "docs.google.com/forms", "random-site.org", "http://192.168.1.5/login", "hdfcbank.com",
             "hdfcbank.co", "binance.com", "binnance.com", "uidai.gov.in.fake.com"]
    for t in tests:
        r = check_url(t)
        print(f"{t:35} -> {r['verdict']:9} {r['reason']} {r['flags']}")