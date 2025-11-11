package domains

// AdDomains contains common advertising domains
var AdDomains = []string{
	// Google Ads
	"googleadservices.com",
	"googlesyndication.com",
	"adservice.google.com",
	"doubleclick.net",
	"googletagservices.com",

	// Facebook/Meta Ads
	"facebook.com/tr",
	"connect.facebook.net",

	// Other Ad Networks
	"advertising.com",
	"adnxs.com",
	"criteo.com",
	"outbrain.com",
	"taboola.com",
	"pubmatic.com",
	"rubiconproject.com",
	"openx.net",
}

// TrackingDomains contains common tracking/analytics domains
var TrackingDomains = []string{
	// Google Analytics
	"google-analytics.com",
	"googletagmanager.com",
	"analytics.google.com",

	// Facebook
	"facebook.com/tr",
	"connect.facebook.net/en_US/fbevents.js",

	// Other Trackers
	"hotjar.com",
	"mouseflow.com",
	"crazyegg.com",
	"mixpanel.com",
	"segment.com",
	"amplitude.com",

	// Research/Ratings
	"scorecardresearch.com",
	"comscore.com",
}

// MalwareDomains contains known malware/phishing test domains
// These are safe test domains for checking if DNS blocks malicious sites
var MalwareDomains = []string{
	// EICAR test domains (safe for testing)
	"malware.testing.google.test",
	"malware.wicar.org",
}

// GetAllAdDomains returns all advertising domains
func GetAllAdDomains() []string {
	return AdDomains
}

// GetAllTrackingDomains returns all tracking domains
func GetAllTrackingDomains() []string {
	return TrackingDomains
}

// GetAllMalwareDomains returns test malware domains
func GetAllMalwareDomains() []string {
	return MalwareDomains
}
