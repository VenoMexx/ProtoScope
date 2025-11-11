package domains

// GeoDomainsRU contains Russian domains for testing
var GeoDomainsRU = []string{
	"vk.com",
	"yandex.ru",
	"mail.ru",
	"ok.ru",
	"rt.com",
	"rambler.ru",
	"lenta.ru",
	"rbc.ru",
}

// GeoDomainsCN contains Chinese domains for testing
var GeoDomainsCN = []string{
	"baidu.com",
	"qq.com",
	"taobao.com",
	"weibo.com",
	"sina.com.cn",
	"jd.com",
	"163.com",
	"sohu.com",
	"bilibili.com",
}

// GeoDomainsIR contains Iranian domains for testing
var GeoDomainsIR = []string{
	"isna.ir",
	"farsnews.ir",
	"tasnimnews.com",
	"mehrnews.com",
	"irna.ir",
	"iranintl.com",
}

// GeoDomainsUS contains US domains for testing
var GeoDomainsUS = []string{
	"google.com",
	"youtube.com",
	"facebook.com",
	"twitter.com",
	"instagram.com",
	"reddit.com",
	"amazon.com",
	"netflix.com",
}

// BlockedInCN contains domains typically blocked in China
var BlockedInCN = []string{
	"google.com",
	"youtube.com",
	"facebook.com",
	"twitter.com",
	"instagram.com",
	"reddit.com",
	"wikipedia.org",
	"nytimes.com",
}

// BlockedInIR contains domains typically blocked in Iran
var BlockedInIR = []string{
	"youtube.com",
	"facebook.com",
	"twitter.com",
	"instagram.com",
	"telegram.org",
	"bbc.com",
	"voanews.com",
}

// GetGeoDomainsForCountry returns domains for a specific country
func GetGeoDomainsForCountry(country string) []string {
	switch country {
	case "RU", "ru":
		return GeoDomainsRU
	case "CN", "cn":
		return GeoDomainsCN
	case "IR", "ir":
		return GeoDomainsIR
	case "US", "us":
		return GeoDomainsUS
	default:
		return []string{}
	}
}

// GetBlockedDomainsForCountry returns typically blocked domains for a country
func GetBlockedDomainsForCountry(country string) []string {
	switch country {
	case "CN", "cn":
		return BlockedInCN
	case "IR", "ir":
		return BlockedInIR
	default:
		return []string{}
	}
}
