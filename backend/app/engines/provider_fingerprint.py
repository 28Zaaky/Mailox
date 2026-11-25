"""
Mail provider & hosting fingerprinting.

Detection vectors:
  - MX hostname patterns
  - SPF include/redirect directives
  - DKIM selector names
  - TXT domain verification tokens
  - SMTP banners
  - IP ASN/RDAP (hosting provider)
  - PTR records
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ProviderMatch:
    name: str
    confidence: float
    signals: list[str] = field(default_factory=list)
    provider_type: str = "esp"   # esp | gateway | selfhosted | hosting | cdn


# ─────────────────────────────────────────────────────────────────────────────
# MX hostname patterns
# ─────────────────────────────────────────────────────────────────────────────

_MX_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Google
    (re.compile(r"\.google\.com$|\.googlemail\.com$|aspmx\.l\.google\.com$", re.I), "Google Workspace", "esp"),
    # Microsoft
    (re.compile(r"\.protection\.outlook\.com$|\.mail\.protection\.outlook\.com$|\.onmicrosoft\.com$", re.I), "Microsoft 365", "esp"),
    # Mimecast
    (re.compile(r"\.mimecast\.com$", re.I), "Mimecast", "gateway"),
    # Proofpoint
    (re.compile(r"\.pphosted\.com$|\.proofpoint\.com$|\.ppe-hosted\.com$", re.I), "Proofpoint", "gateway"),
    # Broadcom/Symantec
    (re.compile(r"\.messagelabs\.com$|\.symanteccloud\.com$|\.mxlogic\.net$", re.I), "Broadcom Email Security", "gateway"),
    # Barracuda
    (re.compile(r"\.barracudanetworks\.com$|\.bsmtp\.com$", re.I), "Barracuda", "gateway"),
    # Cisco IronPort
    (re.compile(r"\.iphmx\.com$", re.I), "Cisco IronPort (Secure Email)", "gateway"),
    # Sophos
    (re.compile(r"\.sophos\.com$|\.reflexion\.net$", re.I), "Sophos Email", "gateway"),
    # FortiMail
    (re.compile(r"\.fortimail\.com$", re.I), "FortiMail", "gateway"),
    # TrendMicro
    (re.compile(r"\.trendmicro\.com$|\.tmsmtp\.com$|\.housingmaps\.com$", re.I), "Trend Micro Email Security", "gateway"),
    # SpamExperts
    (re.compile(r"\.spamexperts\.com$|\.spamrl\.com$", re.I), "SpamExperts", "gateway"),
    # Brevo
    (re.compile(r"smtp\.brevo\.com$|\.sendinblue\.com$|brevo\.com$", re.I), "Brevo (Sendinblue)", "esp"),
    # Mailjet
    (re.compile(r"mx\.mailjet\.com$|in-v3\.mailjet\.com$|mailjet\.com$", re.I), "Mailjet", "esp"),
    # SMTP2Go
    (re.compile(r"\.smtp2go\.com$|smtp2go\.net$", re.I), "SMTP2Go", "esp"),
    # SendGrid
    (re.compile(r"\.sendgrid\.net$", re.I), "SendGrid (Twilio)", "esp"),
    # Mailgun
    (re.compile(r"\.mailgun\.org$|mxa\.mailgun\.org$|mxb\.mailgun\.org$", re.I), "Mailgun", "esp"),
    # Postmark
    (re.compile(r"\.postmarkapp\.com$|\.mtasv\.net$", re.I), "Postmark (ActiveCampaign)", "esp"),
    # SparkPost / Bird
    (re.compile(r"\.sparkpostmail\.com$|\.sparkpost\.com$|\.bird\.com$", re.I), "SparkPost (Bird)", "esp"),
    # AWS SES
    (re.compile(r"\.amazonses\.com$|ses\.amazonaws\.com$|inbound-smtp\.", re.I), "AWS SES", "esp"),
    # Mandrill
    (re.compile(r"\.mandrillapp\.com$", re.I), "Mandrill (Mailchimp Transac)", "esp"),
    # Mailchimp
    (re.compile(r"\.mailchimp\.com$|\.mcsv\.net$", re.I), "Mailchimp", "esp"),
    # Constant Contact
    (re.compile(r"\.constantcontact\.com$|\.roving\.com$", re.I), "Constant Contact", "esp"),
    # Campaign Monitor
    (re.compile(r"\.campaignmonitor\.com$|\.cmail\d+\.com$", re.I), "Campaign Monitor", "esp"),
    # HubSpot
    (re.compile(r"\.hubspot\.com$|\.hs-email\.net$", re.I), "HubSpot", "esp"),
    # Klaviyo
    (re.compile(r"\.klaviyo\.com$|\.klaviyomail\.com$", re.I), "Klaviyo", "esp"),
    # Salesforce Marketing Cloud (ExactTarget)
    (re.compile(r"\.exacttarget\.com$|\.salesforce\.com$|\.exacttargetapis\.com$", re.I), "Salesforce Marketing Cloud", "esp"),
    # Zoho
    (re.compile(r"mx\.zoho\.com$|mx\.zohomail\.com$|mx[0-9]*\.zoho\.eu$", re.I), "Zoho Mail", "esp"),
    # Yandex
    (re.compile(r"\.yandex\.ru$|\.yandex\.net$|mx\.yandex\.net$", re.I), "Yandex 360", "esp"),
    # Apple iCloud
    (re.compile(r"\.icloud\.com$|\.me\.com$|mx\.mail\.me\.com$", re.I), "Apple iCloud Mail", "esp"),
    # Proton Mail
    (re.compile(r"\.protonmail\.ch$|\.proton\.me$|mail\.protonmail\.ch$", re.I), "Proton Mail", "esp"),
    # Fastmail
    (re.compile(r"\.fastmail\.com$|\.fastmail\.fm$|\.messagingengine\.com$", re.I), "Fastmail", "esp"),
    # Tutanota
    (re.compile(r"\.tutanota\.de$|\.tutanota\.com$", re.I), "Tuta (Tutanota)", "esp"),
    # Elastic Email
    (re.compile(r"\.elasticemail\.com$", re.I), "Elastic Email", "esp"),
    # SMTP.com
    (re.compile(r"mx[0-9]*\.smtp\.com$", re.I), "SMTP.com", "esp"),
    # Pepipost / Netcore
    (re.compile(r"\.pepipost\.com$|\.netcorecloud\.net$", re.I), "Netcore (Pepipost)", "esp"),
    # Sendy / Amazon SES wrapper — detected via SES
    # OVH
    (re.compile(r"\.ovh\.net$|ssl0\.ovh\.net$|mx[0-9]*\.ovh\.net$", re.I), "OVH", "esp"),
    # IONOS / 1&1
    (re.compile(r"\.ionos\.com$|\.1and1\.com$|mx[0-9]*\.ionos\.com$", re.I), "IONOS (1&1)", "esp"),
    # GoDaddy
    (re.compile(r"\.godaddy\.com$|\.secureserver\.net$|smtpout\.secureserver\.net$", re.I), "GoDaddy", "esp"),
    # Namecheap
    (re.compile(r"\.namecheap\.com$|mail[0-9]*\.privateemail\.com$", re.I), "Namecheap Private Email", "esp"),
    # Bluehost / Hostgator / cPanel
    (re.compile(r"\.bluehost\.com$|\.hostgator\.com$|\.cpanelemail\.net$", re.I), "cPanel (Bluehost/Hostgator)", "esp"),
    # Rackspace Email
    (re.compile(r"\.emailsrvr\.com$|\.rackspace\.com$", re.I), "Rackspace Email", "esp"),
    # Dreamhost
    (re.compile(r"\.dreamhost\.com$|mx[0-9]*\.dreamhost\.com$", re.I), "DreamHost", "esp"),
    # Hover
    (re.compile(r"mx[0-9]*\.hover\.com$", re.I), "Hover", "esp"),
    # Gandi
    (re.compile(r"\.gandi\.net$|mail\.gandi\.net$", re.I), "Gandi", "esp"),
    # Infomaniak
    (re.compile(r"\.infomaniak\.com$|mail\.infomaniak\.ch$", re.I), "Infomaniak", "esp"),
    # Hetzner
    (re.compile(r"\.hetzner\.com$|mx[0-9]*\.your-server\.de$", re.I), "Hetzner", "hosting"),
    # Register.com
    (re.compile(r"\.register\.com$", re.I), "Register.com", "esp"),
    # Mailbox.org
    (re.compile(r"mx[0-9]*\.mailbox\.org$", re.I), "Mailbox.org", "esp"),
    # MXroute
    (re.compile(r"\.mxroute\.com$", re.I), "MXroute", "esp"),
    # Pobox / Tucows
    (re.compile(r"\.pobox\.com$|\.tucows\.com$", re.I), "Pobox (Tucows)", "esp"),
    # SendPulse
    (re.compile(r"\.sendpulse\.com$", re.I), "SendPulse", "esp"),
    # MailerLite
    (re.compile(r"\.mailerlite\.com$", re.I), "MailerLite", "esp"),
    # ActiveCampaign
    (re.compile(r"\.activecampaign\.com$", re.I), "ActiveCampaign", "esp"),
    # GetResponse
    (re.compile(r"\.getresponse\.com$|\.getresponse360\.com$", re.I), "GetResponse", "esp"),
    # Drip
    (re.compile(r"\.drip\.com$", re.I), "Drip", "esp"),
    # Mailwizz / self-hosted common
]


# ─────────────────────────────────────────────────────────────────────────────
# SPF include / redirect patterns
# ─────────────────────────────────────────────────────────────────────────────

_SPF_INCLUDES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"_spf\.google\.com|google\.com/spf|_netblocks\.google\.com", re.I), "Google Workspace", "esp"),
    (re.compile(r"spf\.protection\.outlook\.com|mail\.protection\.outlook\.com", re.I), "Microsoft 365", "esp"),
    (re.compile(r"amazonses\.com|ses\.amazonaws\.com|_spf\.smtp\.amazon", re.I), "AWS SES", "esp"),
    (re.compile(r"sendgrid\.net", re.I), "SendGrid (Twilio)", "esp"),
    (re.compile(r"mailgun\.org", re.I), "Mailgun", "esp"),
    (re.compile(r"mailjet\.com", re.I), "Mailjet", "esp"),
    (re.compile(r"smtp2go\.com|smtp2go\.net", re.I), "SMTP2Go", "esp"),
    (re.compile(r"brevo\.com|sendinblue\.com", re.I), "Brevo (Sendinblue)", "esp"),
    (re.compile(r"postmarkapp\.com|_spf\.mtasv\.net", re.I), "Postmark (ActiveCampaign)", "esp"),
    (re.compile(r"sparkpostmail\.com|sparkpost\.com|bird\.com", re.I), "SparkPost (Bird)", "esp"),
    (re.compile(r"mandrillapp\.com", re.I), "Mandrill (Mailchimp Transac)", "esp"),
    (re.compile(r"mcsv\.net|mailchimp\.com|chimpified\.com", re.I), "Mailchimp", "esp"),
    (re.compile(r"hubspot\.com|hs-email\.net|sidekick\.io", re.I), "HubSpot", "esp"),
    (re.compile(r"klaviyo\.com|klaviyomail\.com", re.I), "Klaviyo", "esp"),
    (re.compile(r"exacttarget\.com|salesforce\.com|cust-spf\.salesforce\.com", re.I), "Salesforce Marketing Cloud", "esp"),
    (re.compile(r"constantcontact\.com|roving\.com", re.I), "Constant Contact", "esp"),
    (re.compile(r"campaignmonitor\.com", re.I), "Campaign Monitor", "esp"),
    (re.compile(r"mailerlite\.com", re.I), "MailerLite", "esp"),
    (re.compile(r"activecampaign\.com", re.I), "ActiveCampaign", "esp"),
    (re.compile(r"getresponse\.com", re.I), "GetResponse", "esp"),
    (re.compile(r"sendpulse\.com", re.I), "SendPulse", "esp"),
    (re.compile(r"pepipost\.com|netcorecloud\.net", re.I), "Netcore (Pepipost)", "esp"),
    (re.compile(r"smtp\.com", re.I), "SMTP.com", "esp"),
    (re.compile(r"elasticemail\.com", re.I), "Elastic Email", "esp"),
    (re.compile(r"zoho\.com|zohomail\.com", re.I), "Zoho Mail", "esp"),
    (re.compile(r"mimecast\.com", re.I), "Mimecast", "gateway"),
    (re.compile(r"pphosted\.com|proofpoint\.com|ppe-hosted\.com", re.I), "Proofpoint", "gateway"),
    (re.compile(r"barracudanetworks\.com|bsmtp\.com", re.I), "Barracuda", "gateway"),
    (re.compile(r"messagelabs\.com|symanteccloud\.com", re.I), "Broadcom Email Security", "gateway"),
    (re.compile(r"iphmx\.com", re.I), "Cisco IronPort (Secure Email)", "gateway"),
    (re.compile(r"spamexperts\.com", re.I), "SpamExperts", "gateway"),
    (re.compile(r"icloud\.com", re.I), "Apple iCloud Mail", "esp"),
    (re.compile(r"protonmail\.ch|proton\.me", re.I), "Proton Mail", "esp"),
    (re.compile(r"fastmail\.|messagingengine\.com", re.I), "Fastmail", "esp"),
    (re.compile(r"ovh\.net|ovh\.com", re.I), "OVH", "esp"),
    (re.compile(r"ionos\.com|1and1\.com", re.I), "IONOS (1&1)", "esp"),
    (re.compile(r"secureserver\.net|godaddy\.com", re.I), "GoDaddy", "esp"),
    (re.compile(r"privateemail\.com|namecheap\.com", re.I), "Namecheap Private Email", "esp"),
    (re.compile(r"emailsrvr\.com|rackspace\.com", re.I), "Rackspace Email", "esp"),
    (re.compile(r"gandi\.net", re.I), "Gandi", "esp"),
    (re.compile(r"infomaniak\.com|infomaniak\.ch", re.I), "Infomaniak", "esp"),
    (re.compile(r"mailbox\.org", re.I), "Mailbox.org", "esp"),
    (re.compile(r"mxroute\.com", re.I), "MXroute", "esp"),
    (re.compile(r"drip\.com", re.I), "Drip", "esp"),
    (re.compile(r"yandex\.net|yandex\.ru", re.I), "Yandex 360", "esp"),
]


# ─────────────────────────────────────────────────────────────────────────────
# SMTP banner patterns
# ─────────────────────────────────────────────────────────────────────────────

_BANNER_PROVIDERS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bAmazon\s+SES\b", re.I), "AWS SES"),
    (re.compile(r"\bSendGrid\b", re.I), "SendGrid (Twilio)"),
    (re.compile(r"\bMailgun\b", re.I), "Mailgun"),
    (re.compile(r"\bBrevo\b|\bSendinblue\b", re.I), "Brevo (Sendinblue)"),
    (re.compile(r"\bMailjet\b", re.I), "Mailjet"),
    (re.compile(r"\bSMTP2Go\b|\bsmtp2go\b", re.I), "SMTP2Go"),
    (re.compile(r"\bPostmark\b", re.I), "Postmark (ActiveCampaign)"),
    (re.compile(r"\bSparkPost\b", re.I), "SparkPost (Bird)"),
    (re.compile(r"\bMandrill\b", re.I), "Mandrill (Mailchimp Transac)"),
    (re.compile(r"\bMimecast\b", re.I), "Mimecast"),
    (re.compile(r"\bProofpoint\b", re.I), "Proofpoint"),
    (re.compile(r"\bZoho\b", re.I), "Zoho Mail"),
    (re.compile(r"\bOVH\b", re.I), "OVH"),
    (re.compile(r"smtp\.elasticemail\.com", re.I), "Elastic Email"),
    (re.compile(r"\bHubSpot\b|\bHubspot\b", re.I), "HubSpot"),
    (re.compile(r"\bKlaviyo\b", re.I), "Klaviyo"),
    (re.compile(r"\bNetcore\b|\bPepipost\b", re.I), "Netcore (Pepipost)"),
    (re.compile(r"\bMailerlite\b|\bMailerLite\b", re.I), "MailerLite"),
    (re.compile(r"\bActiveCampaign\b", re.I), "ActiveCampaign"),
    (re.compile(r"\bGetResponse\b", re.I), "GetResponse"),
    (re.compile(r"\bInfomaniak\b", re.I), "Infomaniak"),
    (re.compile(r"\bGandi\b", re.I), "Gandi"),
    (re.compile(r"\bHetzner\b", re.I), "Hetzner"),
    (re.compile(r"\bContabo\b", re.I), "Contabo"),
    (re.compile(r"\bExim\b", re.I), "Exim (self-hosted)"),
    (re.compile(r"\bPostfix\b", re.I), "Postfix (self-hosted)"),
    (re.compile(r"\bSendmail\b", re.I), "Sendmail (self-hosted)"),
    (re.compile(r"\bMicrosoft\s+ESMTP\s+MAIL", re.I), "Microsoft Exchange (self-hosted)"),
    (re.compile(r"\bqmail\b", re.I), "qmail (self-hosted)"),
    (re.compile(r"\bDovecot\b", re.I), "Dovecot (self-hosted)"),
    (re.compile(r"\bhMailServer\b", re.I), "hMailServer (self-hosted)"),
    (re.compile(r"\bMailEnable\b", re.I), "MailEnable (self-hosted)"),
    (re.compile(r"\bZimbra\b", re.I), "Zimbra (self-hosted)"),
    (re.compile(r"\bOpenSMTPD\b|\bsmtpd\b", re.I), "OpenSMTPD (self-hosted)"),
]

# Banner → hosting provider (when MTA is self-hosted)
_BANNER_MTA_VERSION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bExim\s+([\d.]+)", re.I), "Exim"),
    (re.compile(r"\bPostfix\b", re.I), "Postfix"),
    (re.compile(r"\bSendmail\s+([\d./]+)", re.I), "Sendmail"),
    (re.compile(r"\bMicrosoft\s+ESMTP\s+MAIL\s+Service", re.I), "Microsoft Exchange"),
    (re.compile(r"\bqmail\b", re.I), "qmail"),
    (re.compile(r"\bDovecot\b", re.I), "Dovecot"),
    (re.compile(r"\bZimbra\b", re.I), "Zimbra"),
    (re.compile(r"\bHalon\b", re.I), "Halon"),
    (re.compile(r"\bPowerMTA\b|\bPort25\b", re.I), "PowerMTA"),
]


# ─────────────────────────────────────────────────────────────────────────────
# DKIM selector patterns
# ─────────────────────────────────────────────────────────────────────────────

_DKIM_SELECTORS: list[tuple[re.Pattern, str]] = [
    # Brevo / Sendinblue
    (re.compile(r"^brevo\d*$|^sendinblue\d*$", re.I), "Brevo (Sendinblue)"),
    # SendGrid — k1..k9, s1..s9, em*
    (re.compile(r"^k\d+$", re.I), "SendGrid (Twilio)"),
    (re.compile(r"^s\d+$", re.I), "SendGrid (Twilio)"),
    (re.compile(r"^em\d*$", re.I), "SendGrid (Twilio)"),
    # Mailjet
    (re.compile(r"^mailjet\d*$", re.I), "Mailjet"),
    # SMTP2Go
    (re.compile(r"^smtp2go\d*$", re.I), "SMTP2Go"),
    # Postmark
    (re.compile(r"^pm\d+$", re.I), "Postmark (ActiveCampaign)"),
    # Mandrill/Mailchimp
    (re.compile(r"^mx\d+$", re.I), "Mandrill/Mailchimp"),
    (re.compile(r"^mandrill\d*$", re.I), "Mandrill (Mailchimp Transac)"),
    (re.compile(r"^mailchimp\d*$", re.I), "Mailchimp"),
    # Microsoft 365
    (re.compile(r"^selector[12]$", re.I), "Microsoft 365"),
    # Google Workspace
    (re.compile(r"^google$", re.I), "Google Workspace"),
    (re.compile(r"^20161025$|^20210112$|^\d{8}$", re.I), "Google Workspace"),
    # AWS SES
    (re.compile(r"^ses$|^amazonses$", re.I), "AWS SES"),
    # Mailgun
    (re.compile(r"^mg\d*$|^mailo\d*$", re.I), "Mailgun"),
    (re.compile(r"^mailgun\d*$", re.I), "Mailgun"),
    # SparkPost/Bird
    (re.compile(r"^scph\d+$", re.I), "SparkPost (Bird)"),
    # HubSpot
    (re.compile(r"^hs[12]$|^hubspot\d*$", re.I), "HubSpot"),
    # Klaviyo
    (re.compile(r"^klaviyo\d*$|^kl\d*$", re.I), "Klaviyo"),
    # Salesforce / ExactTarget
    (re.compile(r"^et\d+$|^exacttarget\d*$|^sfmc\d*$", re.I), "Salesforce Marketing Cloud"),
    # Campaign Monitor
    (re.compile(r"^cm\d+$|^campaignmonitor\d*$", re.I), "Campaign Monitor"),
    # Mailerlite
    (re.compile(r"^mailerlite\d*$|^ml\d+$", re.I), "MailerLite"),
    # ActiveCampaign
    (re.compile(r"^ac\d+$|^activecampaign\d*$", re.I), "ActiveCampaign"),
    # SendPulse
    (re.compile(r"^sendpulse\d*$|^sp\d+$", re.I), "SendPulse"),
    # Constant Contact
    (re.compile(r"^cc\d+$|^constantcontact\d*$", re.I), "Constant Contact"),
    # Zoho
    (re.compile(r"^zoho\d*$", re.I), "Zoho Mail"),
    # Proton Mail
    (re.compile(r"^protonmail\d*$|^proton\d*$", re.I), "Proton Mail"),
    # Netcore/Pepipost
    (re.compile(r"^pepipost\d*$|^netcore\d*$", re.I), "Netcore (Pepipost)"),
    # Elastic Email
    (re.compile(r"^elastic\d*$|^ee\d*$", re.I), "Elastic Email"),
    # Infomaniak
    (re.compile(r"^infomaniak\d*$", re.I), "Infomaniak"),
    # Gandi
    (re.compile(r"^gandi\d*$", re.I), "Gandi"),
    # OVH
    (re.compile(r"^ovh\d*$", re.I), "OVH"),
]


# ─────────────────────────────────────────────────────────────────────────────
# TXT domain verification token patterns
# ─────────────────────────────────────────────────────────────────────────────

_TXT_TOKENS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^brevo-code:", re.I), "Brevo (Sendinblue)", "esp"),
    (re.compile(r"^sendinblue-code:", re.I), "Brevo (Sendinblue)", "esp"),
    (re.compile(r"^sendgrid-domain-verify", re.I), "SendGrid (Twilio)", "esp"),
    (re.compile(r"^mailgun-verification", re.I), "Mailgun", "esp"),
    (re.compile(r"^mailjet-verification|^mailjet\.", re.I), "Mailjet", "esp"),
    (re.compile(r"^smtp2go-domain-verification", re.I), "SMTP2Go", "esp"),
    (re.compile(r"^postmark-domain-confirm|^v=DKIM1.*postmark", re.I), "Postmark (ActiveCampaign)", "esp"),
    (re.compile(r"^sparkpost-verification", re.I), "SparkPost (Bird)", "esp"),
    (re.compile(r"^ses-domain-verification|^amazonses:", re.I), "AWS SES", "esp"),
    (re.compile(r"^protonmail-verification", re.I), "Proton Mail", "esp"),
    (re.compile(r"^mimecast-verification", re.I), "Mimecast", "gateway"),
    (re.compile(r"^zoho-verification|^zoho:", re.I), "Zoho Mail", "esp"),
    (re.compile(r"^klaviyo-site-verification", re.I), "Klaviyo", "esp"),
    (re.compile(r"^hubspot-developer-verification|^hs-site-verification", re.I), "HubSpot", "esp"),
    (re.compile(r"^elasticemail-domain-verification", re.I), "Elastic Email", "esp"),
    (re.compile(r"^mailerlite-domain-verification", re.I), "MailerLite", "esp"),
    (re.compile(r"^activecampaign-domain-verify", re.I), "ActiveCampaign", "esp"),
    (re.compile(r"^getresponse-verification", re.I), "GetResponse", "esp"),
    (re.compile(r"^sendpulse-domain-verify", re.I), "SendPulse", "esp"),
    (re.compile(r"^constant-contact-site", re.I), "Constant Contact", "esp"),
    (re.compile(r"^salesforce-domain-verify", re.I), "Salesforce Marketing Cloud", "esp"),
    (re.compile(r"^drip-domain-verify", re.I), "Drip", "esp"),
    (re.compile(r"^pepipost-domain-verify", re.I), "Netcore (Pepipost)", "esp"),
    (re.compile(r"^smtp\.com-domain-verify", re.I), "SMTP.com", "esp"),
    (re.compile(r"^barracuda-domain-verify", re.I), "Barracuda", "gateway"),
    (re.compile(r"^proofpoint-domain-verify", re.I), "Proofpoint", "gateway"),
    # Generic ownership tokens that hint at provider context
    (re.compile(r"^v=DKIM1.*brevo", re.I), "Brevo (Sendinblue)", "esp"),
    (re.compile(r"^apple-domain-verify", re.I), "Apple iCloud Mail", "esp"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Hosting provider detection via IP ASN descriptions and PTR patterns
# ─────────────────────────────────────────────────────────────────────────────

_ASN_HOSTING: list[tuple[re.Pattern, str]] = [
    (re.compile(r"contabo", re.I), "Contabo"),
    (re.compile(r"hetzner", re.I), "Hetzner"),
    (re.compile(r"ovh|kimsufi|so you start", re.I), "OVH"),
    (re.compile(r"amazon|aws|ec2|cloudfront", re.I), "Amazon Web Services"),
    (re.compile(r"google|gcp|google cloud", re.I), "Google Cloud"),
    (re.compile(r"microsoft|azure", re.I), "Microsoft Azure"),
    (re.compile(r"digitalocean|digital ocean", re.I), "DigitalOcean"),
    (re.compile(r"linode|akamai", re.I), "Linode/Akamai"),
    (re.compile(r"vultr", re.I), "Vultr"),
    (re.compile(r"scaleway", re.I), "Scaleway"),
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
    (re.compile(r"fastly", re.I), "Fastly"),
    (re.compile(r"rackspace", re.I), "Rackspace"),
    (re.compile(r"leaseweb", re.I), "LeaseWeb"),
    (re.compile(r"choopa|vultr", re.I), "Vultr"),
    (re.compile(r"ionos|1&1", re.I), "IONOS"),
    (re.compile(r"godaddy", re.I), "GoDaddy"),
    (re.compile(r"namecheap", re.I), "Namecheap"),
    (re.compile(r"hostgator|bluehost|endurance", re.I), "EIG (Bluehost/Hostgator)"),
    (re.compile(r"dreamhost", re.I), "DreamHost"),
    (re.compile(r"siteground", re.I), "SiteGround"),
    (re.compile(r"wpengine", re.I), "WP Engine"),
    (re.compile(r"kinsta", re.I), "Kinsta"),
    (re.compile(r"netlify", re.I), "Netlify"),
    (re.compile(r"vercel", re.I), "Vercel"),
    (re.compile(r"infomaniak", re.I), "Infomaniak"),
    (re.compile(r"gandi", re.I), "Gandi"),
    (re.compile(r"online\.net|proxad|free\.fr|iliad", re.I), "Free/Iliad"),
    (re.compile(r"sfr|numericable", re.I), "SFR"),
    (re.compile(r"orange|wanadoo", re.I), "Orange"),
    (re.compile(r"telenet|proximus|belgacom", re.I), "Proximus"),
    (re.compile(r"strato", re.I), "Strato"),
    (re.compile(r"hosteurope|web\.de|gmx\.", re.I), "Host Europe / GMX"),
    (re.compile(r"claranet", re.I), "Claranet"),
    (re.compile(r"ntt|softbank|docomo", re.I), "NTT/Softbank"),
    (re.compile(r"alibaba|aliyun", re.I), "Alibaba Cloud"),
    (re.compile(r"tencent|qcloud", re.I), "Tencent Cloud"),
    (re.compile(r"huawei cloud", re.I), "Huawei Cloud"),
    (re.compile(r"ibm cloud|softlayer", re.I), "IBM Cloud"),
    (re.compile(r"telstra", re.I), "Telstra"),
    (re.compile(r"comcast", re.I), "Comcast"),
    (re.compile(r"verizon|frontier", re.I), "Verizon"),
]

_PTR_HOSTING: list[tuple[re.Pattern, str]] = [
    (re.compile(r"contabo|your-server\.de.*contabo", re.I), "Contabo"),
    (re.compile(r"hetzner\.com|your-server\.de", re.I), "Hetzner"),
    (re.compile(r"ovh\.net|kimsufi\.com|rbx\.|sbg\.|gra\.", re.I), "OVH"),
    (re.compile(r"ec2\.amazonaws\.com|aws\.com", re.I), "Amazon Web Services"),
    (re.compile(r"googleusercontent\.com|google\.com", re.I), "Google Cloud"),
    (re.compile(r"azure\.com|windows\.net|microsoft\.com", re.I), "Microsoft Azure"),
    (re.compile(r"digitalocean\.com", re.I), "DigitalOcean"),
    (re.compile(r"linode\.com|members\.linode\.com", re.I), "Linode/Akamai"),
    (re.compile(r"vultr\.com|choopa\.net", re.I), "Vultr"),
    (re.compile(r"scaleway\.com|online\.net", re.I), "Scaleway"),
    (re.compile(r"cloudflare\.com", re.I), "Cloudflare"),
    (re.compile(r"rackspace\.com", re.I), "Rackspace"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Public functions
# ─────────────────────────────────────────────────────────────────────────────

def fingerprint_from_mx(mx_hostnames: list[str]) -> list[ProviderMatch]:
    matches: dict[str, ProviderMatch] = {}
    for hostname in mx_hostnames:
        hostname = hostname.rstrip(".")
        for pattern, provider, ptype in _MX_PATTERNS:
            if pattern.search(hostname):
                if provider not in matches:
                    matches[provider] = ProviderMatch(name=provider, confidence=0.95, provider_type=ptype)
                matches[provider].signals.append(f"MX: {hostname}")
    return list(matches.values())


def fingerprint_from_spf(spf_record: str) -> list[ProviderMatch]:
    matches: dict[str, ProviderMatch] = {}
    for pattern, provider, ptype in _SPF_INCLUDES:
        m = pattern.search(spf_record)
        if m:
            if provider not in matches:
                matches[provider] = ProviderMatch(name=provider, confidence=0.90, provider_type=ptype)
            matches[provider].signals.append(f"SPF include: {m.group(0)}")
    return list(matches.values())


def fingerprint_from_banner(banner: str) -> Optional[ProviderMatch]:
    for pattern, provider in _BANNER_PROVIDERS:
        if pattern.search(banner):
            ptype = "selfhosted" if "self-hosted" in provider else "esp"
            return ProviderMatch(
                name=provider,
                confidence=0.88,
                signals=[f"SMTP banner: {banner[:80]}"],
                provider_type=ptype,
            )
    return None


def fingerprint_mta_from_banner(banner: str) -> Optional[tuple[str, Optional[str]]]:
    """Return (mta_name, version_or_None) from banner."""
    for pattern, name in _BANNER_MTA_VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            version = m.group(1) if m.lastindex else None
            return name, version
    return None


def fingerprint_from_dkim_selectors(selectors: list[str]) -> list[ProviderMatch]:
    matches: dict[str, ProviderMatch] = {}
    for sel in selectors:
        for pattern, provider in _DKIM_SELECTORS:
            if pattern.match(sel):
                if provider not in matches:
                    matches[provider] = ProviderMatch(name=provider, confidence=0.72, provider_type="esp")
                matches[provider].signals.append(f"DKIM selector: {sel}")
    return list(matches.values())


def fingerprint_from_txt_records(txt_records: list[str]) -> list[ProviderMatch]:
    matches: dict[str, ProviderMatch] = {}
    for txt in txt_records:
        for pattern, provider, ptype in _TXT_TOKENS:
            if pattern.search(txt):
                if provider not in matches:
                    matches[provider] = ProviderMatch(name=provider, confidence=0.93, provider_type=ptype)
                matches[provider].signals.append(f"TXT token: {txt[:70]}")
    return list(matches.values())


def fingerprint_hosting_from_asn(asn_description: str) -> Optional[ProviderMatch]:
    """Identify hosting provider from RDAP/WHOIS ASN description."""
    for pattern, provider in _ASN_HOSTING:
        if pattern.search(asn_description):
            return ProviderMatch(
                name=provider,
                confidence=0.85,
                signals=[f"ASN: {asn_description[:80]}"],
                provider_type="hosting",
            )
    return None


def fingerprint_hosting_from_ptr(ptr: str) -> Optional[ProviderMatch]:
    """Identify hosting provider from PTR (reverse DNS) record."""
    for pattern, provider in _PTR_HOSTING:
        if pattern.search(ptr):
            return ProviderMatch(
                name=provider,
                confidence=0.80,
                signals=[f"PTR: {ptr}"],
                provider_type="hosting",
            )
    return None


def fingerprint_selfhosted_from_mx(mx_hostnames: list[str], domain: str) -> list[ProviderMatch]:
    """
    Signal self-hosted MTA when MX hostname is a subdomain of the target domain.
    E.g., mail.example.com MX for example.com = almost certainly self-hosted.
    """
    matches: list[ProviderMatch] = []
    domain_lower = domain.lower().rstrip(".")
    for host in mx_hostnames:
        host_lower = host.lower().rstrip(".")
        # MX is a subdomain of target (mail.example.com) or the domain itself
        if host_lower == domain_lower or host_lower.endswith("." + domain_lower):
            matches.append(ProviderMatch(
                name="Self-hosted MTA",
                confidence=0.75,
                signals=[f"MX {host} is a subdomain of {domain}"],
                provider_type="selfhosted",
            ))
            break
    return matches


async def fingerprint_hosting_from_rdap(ip: str) -> Optional[ProviderMatch]:
    """Identify hosting provider from RDAP IP lookup (rdap.org)."""
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"https://rdap.org/ip/{ip}",
                headers={"Accept": "application/json"},
                follow_redirects=True,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            # Try network name and org name fields
            network_name = data.get("name", "") or ""
            handle = data.get("handle", "") or ""
            # entities: array of {roles, vcardArray}
            org_names: list[str] = [network_name, handle]
            for ent in data.get("entities", []):
                for vcard in ent.get("vcardArray", []):
                    if isinstance(vcard, list):
                        for field in vcard:
                            if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                                org_names.append(str(field[3]))
            combined = " ".join(filter(None, org_names))
            match = fingerprint_hosting_from_asn(combined)
            if match:
                match.confidence = 0.90
                match.signals = [f"RDAP: {combined[:100]}"]
                return match
            return None
    except Exception:
        return None


def merge_provider_matches(all_matches: list[ProviderMatch]) -> list[ProviderMatch]:
    """Merge duplicate provider matches, summing signals and boosting confidence."""
    merged: dict[str, ProviderMatch] = {}
    for m in all_matches:
        if m.name not in merged:
            merged[m.name] = ProviderMatch(
                name=m.name,
                confidence=m.confidence,
                signals=list(m.signals),
                provider_type=m.provider_type,
            )
        else:
            existing = merged[m.name]
            existing.signals.extend(m.signals)
            # Each extra signal bumps confidence slightly, capped at 0.99
            existing.confidence = min(0.99, existing.confidence + 0.03 * len(m.signals))
    return sorted(merged.values(), key=lambda x: -x.confidence)
