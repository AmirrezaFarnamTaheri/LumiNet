package presets

// LabeledRange represents a subnet range with a geographic/provider label.
type LabeledRange struct {
	Cidr            string `json:"cidr"`
	Label           string `json:"label"`
	DefaultSelected bool   `json:"default_selected"`
}

// CDNPreset represents a pre-configured CDN range list for scanning or spoofing.
type CDNPreset struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Snis   []string       `json:"snis"`
	Ranges []LabeledRange `json:"ranges"`
}

// DoHPreset represents a pre-configured secure DNS-over-HTTPS resolver.
type DoHPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description"`
}

// GetCDNPresets returns the preset configurations compiled from field operations (including Iran-specific ISP targets).
func GetCDNPresets() []CDNPreset {
	return []CDNPreset{
		{
			ID:   "cloudflare",
			Name: "Cloudflare",
			Snis: []string{
				"www.cloudflare.com",
				"discord.com",
				"www.cloudflareapps.com",
				"cdnjs.cloudflare.com",
				"www.shopify.com",
				"www.medium.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "162.159.192.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "162.159.193.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "162.159.195.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "188.114.96.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "188.114.97.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "188.114.98.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "188.114.99.0/24", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "104.16.0.0/13", Label: "Cloudflare", DefaultSelected: true},
				{Cidr: "104.24.0.0/14", Label: "Cloudflare", DefaultSelected: true},
			},
		},
		{
			ID:   "fastly",
			Name: "Fastly",
			Snis: []string{
				"www.fastly.com",
				"www.reddit.com",
				"www.nytimes.com",
				"www.imgur.com",
				"www.spotify.com",
				"developer.mozilla.org",
			},
			Ranges: []LabeledRange{
				{Cidr: "151.101.0.0/16", Label: "Fastly", DefaultSelected: true},
				{Cidr: "199.232.0.0/16", Label: "Fastly", DefaultSelected: true},
			},
		},
		{
			ID:   "google",
			Name: "Google CDN",
			Snis: []string{
				"fonts.googleapis.com",
				"ajax.googleapis.com",
				"storage.googleapis.com",
				"www.gstatic.com",
				"ssl.gstatic.com",
				"accounts.google.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "34.143.0.0/24", Label: "Cloud Run", DefaultSelected: true},
				{Cidr: "34.160.0.0/24", Label: "Cloud", DefaultSelected: true},
				{Cidr: "34.96.0.0/24", Label: "Cloud", DefaultSelected: true},
				{Cidr: "35.186.0.0/24", Label: "Cloud", DefaultSelected: true},
				{Cidr: "64.233.160.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "66.249.80.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "74.125.0.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "142.250.0.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "172.217.0.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "216.58.192.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "35.201.0.0/24", Label: "Cloud", DefaultSelected: true},
				{Cidr: "34.117.0.0/24", Label: "Cloud", DefaultSelected: true},
			},
		},
		{
			ID:   "amazon",
			Name: "Amazon CloudFront",
			Snis: []string{
				"d1.cloudfront.net",
				"d2.cloudfront.net",
				"d3.cloudfront.net",
				"aws.cloudfront.net",
				"s3.amazonaws.com",
				"edge.cloudfront.net",
			},
			Ranges: []LabeledRange{
				{Cidr: "13.32.0.0/24", Label: "US", DefaultSelected: true},
				{Cidr: "13.35.0.0/24", Label: "US", DefaultSelected: true},
				{Cidr: "52.46.0.0/24", Label: "US", DefaultSelected: true},
				{Cidr: "54.192.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "54.230.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "99.84.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "130.176.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "143.204.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "205.251.192.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "54.239.128.0/24", Label: "Global", DefaultSelected: true},
			},
		},
		{
			ID:   "azure",
			Name: "Microsoft Azure",
			Snis: []string{
				"ajax.aspnetcdn.com",
				"az416426.vo.msecnd.net",
				"az784690.vo.msecnd.net",
				"cdn.office.net",
				"static.azureedge.net",
				"az.msecnd.net",
			},
			Ranges: []LabeledRange{
				{Cidr: "13.107.4.0/24", Label: "Core", DefaultSelected: true},
				{Cidr: "23.96.0.0/24", Label: "US", DefaultSelected: true},
				{Cidr: "40.64.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "52.224.0.0/24", Label: "US", DefaultSelected: true},
				{Cidr: "104.208.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "137.116.0.0/24", Label: "Global", DefaultSelected: true},
				{Cidr: "168.61.0.0/24", Label: "US", DefaultSelected: true},
			},
		},
		{
			ID:   "iran-isp",
			Name: "Iran ISP Pre-tested (MCI / Irancell / Rightel / Shatel / Asiatech / Pars)",
			Snis: []string{
				"a248.e.akamai.net",
				"a77.net.akamai.net",
				"a104.net.akamai.net",
				"a184.net.akamai.net",
				"ds-aksb.akamaized.net",
				"ak.net.akamaized.net",
			},
			Ranges: []LabeledRange{
				{Cidr: "184.24.77.42/32", Label: "MCI", DefaultSelected: true},
				{Cidr: "184.24.77.32/32", Label: "MCI", DefaultSelected: true},
				{Cidr: "185.200.232.49/32", Label: "MCI", DefaultSelected: true},
				{Cidr: "23.48.23.151/32", Label: "MCI", DefaultSelected: true},
				{Cidr: "104.112.146.82/32", Label: "MCI", DefaultSelected: true},
				{Cidr: "184.24.77.7/32", Label: "MCI", DefaultSelected: true},
				{Cidr: "2.22.250.149/32", Label: "Irancell", DefaultSelected: true},
				{Cidr: "23.58.193.140/32", Label: "Irancell", DefaultSelected: true},
				{Cidr: "184.24.77.5/32", Label: "Irancell", DefaultSelected: true},
				{Cidr: "185.200.232.50/32", Label: "Irancell", DefaultSelected: true},
				{Cidr: "23.43.237.239/32", Label: "Irancell", DefaultSelected: true},
				{Cidr: "92.16.53.11/32", Label: "Irancell", DefaultSelected: true},
				{Cidr: "184.24.77.21/32", Label: "Rightel", DefaultSelected: true},
				{Cidr: "185.200.232.42/32", Label: "Rightel", DefaultSelected: true},
				{Cidr: "23.48.23.186/32", Label: "Rightel", DefaultSelected: true},
				{Cidr: "72.246.28.3/32", Label: "Rightel", DefaultSelected: true},
				{Cidr: "92.122.0.1/32", Label: "Rightel", DefaultSelected: true},
				{Cidr: "184.24.77.11/32", Label: "Shatel", DefaultSelected: true},
				{Cidr: "185.200.232.41/32", Label: "Shatel", DefaultSelected: true},
				{Cidr: "23.48.23.133/32", Label: "Shatel", DefaultSelected: true},
				{Cidr: "2.19.126.81/32", Label: "Shatel", DefaultSelected: true},
				{Cidr: "104.64.0.5/32", Label: "Shatel", DefaultSelected: true},
				{Cidr: "184.24.77.16/32", Label: "Asiatech", DefaultSelected: true},
				{Cidr: "185.200.232.43/32", Label: "Asiatech", DefaultSelected: true},
				{Cidr: "23.48.23.195/32", Label: "Asiatech", DefaultSelected: true},
				{Cidr: "104.64.0.6/32", Label: "Asiatech", DefaultSelected: true},
				{Cidr: "184.24.77.36/32", Label: "ParsOnline", DefaultSelected: true},
				{Cidr: "185.200.232.8/32", Label: "ParsOnline", DefaultSelected: true},
				{Cidr: "23.48.23.178/32", Label: "ParsOnline", DefaultSelected: true},
				{Cidr: "104.64.0.7/32", Label: "ParsOnline", DefaultSelected: true},
			},
		},
		{
			ID:   "warp",
			Name: "Cloudflare WARP",
			Snis: []string{
				"engage.cloudflareclient.com",
				"private-charter.cloudflareclient.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "8.6.112.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.34.70.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.34.146.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.35.211.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.39.125.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.39.204.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.39.214.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "8.47.69.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "162.159.192.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "162.159.195.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "188.114.96.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "188.114.97.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "188.114.98.0/24", Label: "WARP", DefaultSelected: true},
				{Cidr: "188.114.99.0/24", Label: "WARP", DefaultSelected: true},
			},
		},
		{
			ID:   "akamai",
			Name: "Akamai CDN",
			Snis: []string{
				"a248.e.akamai.net",
				"a77.net.akamai.net",
				"a104.net.akamai.net",
				"a184.net.akamai.net",
			},
			Ranges: []LabeledRange{
				{Cidr: "2.16.0.0/13", Label: "Akamai", DefaultSelected: true},
				{Cidr: "23.0.0.0/12", Label: "Akamai", DefaultSelected: true},
				{Cidr: "23.32.0.0/11", Label: "Akamai", DefaultSelected: true},
				{Cidr: "23.64.0.0/14", Label: "Akamai", DefaultSelected: true},
				{Cidr: "69.192.0.0/16", Label: "Akamai", DefaultSelected: true},
				{Cidr: "72.246.0.0/15", Label: "Akamai", DefaultSelected: true},
				{Cidr: "88.221.0.0/16", Label: "Akamai", DefaultSelected: true},
				{Cidr: "104.64.0.0/10", Label: "Akamai", DefaultSelected: true},
				{Cidr: "184.24.0.0/13", Label: "Akamai", DefaultSelected: true},
				{Cidr: "184.84.0.0/14", Label: "Akamai", DefaultSelected: true},
			},
		},
		{
			ID:   "arvancloud",
			Name: "Arvan Cloud",
			Snis: []string{
				"www.arvancloud.ir",
				"rdisk.arvancloud.ir",
			},
			Ranges: []LabeledRange{
				{Cidr: "2.144.3.128/28", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "37.32.16.0/27", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "37.32.17.0/27", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "37.32.18.0/27", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "37.32.19.0/27", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "94.101.182.0/27", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "178.131.120.48/28", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "185.143.232.0/22", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "185.215.232.0/22", Label: "ArvanCloud", DefaultSelected: true},
				{Cidr: "188.229.116.16/30", Label: "ArvanCloud", DefaultSelected: true},
			},
		},
		{
			ID:   "derakcloud",
			Name: "Derak Cloud",
			Snis: []string{
				"derak.cloud",
				"panel.derak.cloud",
			},
			Ranges: []LabeledRange{
				{Cidr: "5.145.115.0/24", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "5.145.118.0/23", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "45.63.43.128/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "45.77.87.48/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "89.222.113.80/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "116.202.90.176/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "159.69.229.224/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "165.232.92.112/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "178.62.222.208/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "185.24.252.192/27", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "185.24.254.64/27", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "185.24.255.192/27", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "185.24.255.224/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "192.168.204.48/28", Label: "DerakCloud", DefaultSelected: true},
				{Cidr: "207.148.25.64/28", Label: "DerakCloud", DefaultSelected: true},
			},
		},
		{
			ID:   "netlify",
			Name: "Netlify",
			Snis: []string{
				"netlify.com",
				"www.netlify.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "3.33.128.0/17", Label: "Netlify", DefaultSelected: true},
				{Cidr: "13.32.0.0/15", Label: "Netlify", DefaultSelected: true},
				{Cidr: "13.35.0.0/16", Label: "Netlify", DefaultSelected: true},
				{Cidr: "18.64.0.0/14", Label: "Netlify", DefaultSelected: true},
				{Cidr: "44.226.105.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "50.7.4.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "50.7.85.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "50.7.87.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "44.235.184.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "52.84.0.0/15", Label: "Netlify", DefaultSelected: true},
				{Cidr: "35.157.26.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "63.176.8.0/24", Label: "Netlify", DefaultSelected: true},
				{Cidr: "54.182.0.0/16", Label: "Netlify", DefaultSelected: true},
				{Cidr: "99.83.128.0/17", Label: "Netlify", DefaultSelected: true},
				{Cidr: "162.159.128.0/20", Label: "Netlify", DefaultSelected: true},
			},
		},
		{
			ID:   "vercel",
			Name: "Vercel",
			Snis: []string{
				"vercel.com",
				"www.vercel.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "64.29.17.0/24", Label: "Vercel", DefaultSelected: true},
				{Cidr: "64.29.18.0/24", Label: "Vercel", DefaultSelected: true},
				{Cidr: "64.29.19.0/24", Label: "Vercel", DefaultSelected: true},
				{Cidr: "66.33.60.0/24", Label: "Vercel", DefaultSelected: true},
				{Cidr: "66.33.61.0/24", Label: "Vercel", DefaultSelected: true},
				{Cidr: "76.76.21.0/24", Label: "Vercel", DefaultSelected: true},
				{Cidr: "76.223.126.0/24", Label: "Vercel", DefaultSelected: true},
			},
		},
		{
			ID:   "bunnycdn",
			Name: "BunnyCDN",
			Snis: []string{
				"bunny.net",
				"bunnycdn.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "89.187.160.0/19", Label: "BunnyCDN", DefaultSelected: true},
				{Cidr: "147.75.0.0/16", Label: "BunnyCDN", DefaultSelected: true},
			},
		},
		{
			ID:   "gcore",
			Name: "Gcore",
			Snis: []string{
				"gcore.com",
				"gcorelabs.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "92.223.0.0/16", Label: "Gcore", DefaultSelected: true},
				{Cidr: "95.85.0.0/16", Label: "Gcore", DefaultSelected: true},
				{Cidr: "185.158.0.0/16", Label: "Gcore", DefaultSelected: true},
			},
		},
		{
			ID:   "iranserver",
			Name: "IranServer CDN",
			Snis: []string{
				"iranserver.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "5.182.45.23/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "5.182.45.37/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "45.159.114.11/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "87.98.249.55/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "93.127.182.21/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "93.127.182.24/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "94.143.229.14/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "94.182.97.44/31", Label: "IranServer", DefaultSelected: true},
				{Cidr: "94.182.97.46/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "168.119.4.117/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "185.116.162.15/32", Label: "IranServer", DefaultSelected: true},
				{Cidr: "185.116.162.19/32", Label: "IranServer", DefaultSelected: true},
			},
		},
		{
			ID:   "parspack",
			Name: "ParsPack CDN",
			Snis: []string{
				"parspack.com",
			},
			Ranges: []LabeledRange{
				{Cidr: "2.144.23.191/32", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "5.135.72.112/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "5.160.143.64/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "31.214.248.208/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.32.131.160/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.32.154.64/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.76.132.16/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.77.211.208/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.77.211.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.77.223.80/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "45.139.11.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "46.20.41.224/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "64.176.15.176/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "64.176.64.80/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "65.20.72.128/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "65.20.113.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "77.237.66.128/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "79.175.148.128/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "84.17.42.224/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "87.236.161.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "89.36.162.32/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "89.187.169.48/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "91.228.186.48/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "94.182.153.64/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.179.140.112/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.179.164.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.179.220.128/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.179.254.176/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.211.188.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.211.219.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.211.240.112/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "95.211.250.112/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "130.185.74.48/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "130.185.79.128/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "139.84.177.16/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "139.84.236.0/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "144.202.58.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "144.202.78.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "144.202.114.128/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "155.138.162.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "158.51.122.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "158.247.223.48/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "167.179.93.112/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "171.22.26.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "178.22.120.192/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "185.8.173.0/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "185.8.174.144/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "185.8.175.208/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "185.110.191.240/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "185.204.197.0/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "185.208.175.144/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "194.5.188.32/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "195.88.208.176/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "195.181.174.64/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "195.248.241.160/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "195.248.242.192/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "199.247.3.16/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "207.148.69.96/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "208.85.22.32/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "213.183.48.16/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "216.238.117.0/28", Label: "ParsPack", DefaultSelected: true},
				{Cidr: "217.197.97.48/28", Label: "ParsPack", DefaultSelected: true},
			},
		},
	}
}

// GetWarpPorts returns the list of candidate WARP ports from the field logs.
func GetWarpPorts() []int {
	return []int{
		500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946,
		955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408,
		2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281,
		7559, 8319, 8742, 8854, 8886,
	}
}

// GetDoHPresets returns the list of popular secure DoH resolvers.
func GetDoHPresets() []DoHPreset {
	return []DoHPreset{
		{ID: "cloudflare", Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query", Description: "Fast and private DNS service"},
		{ID: "google-public-dns", Name: "Google Public DNS", URL: "https://dns.google/dns-query", Description: "Google's free DNS service"},
		{ID: "opendns", Name: "OpenDNS", URL: "https://doh.opendns.com/dns-query", Description: "Secure DNS service with content filtering"},
		{ID: "quad9", Name: "Quad9", URL: "https://dns.quad9.net/dns-query", Description: "Security-focused DNS service"},
		{ID: "quad9-secured", Name: "Quad9 Secured", URL: "https://dns9.quad9.net/dns-query", Description: "Quad9 secured variant"},
		{ID: "quad9-unsecured", Name: "Quad9 Unsecured", URL: "https://dns10.quad9.net/dns-query", Description: "Quad9 unsecured/no-blocking variant"},
		{ID: "quad9-secured-ecs", Name: "Quad9 Secured + ECS", URL: "https://dns11.quad9.net/dns-query", Description: "Quad9 secured variant with EDNS Client Subnet support"},
		{ID: "adguard-dns", Name: "AdGuard DNS", URL: "https://dns.adguard.com/dns-query", Description: "Privacy-focused DNS with ad blocking"},
		{ID: "cleanbrowsing", Name: "CleanBrowsing", URL: "https://doh.cleanbrowsing.org/doh/family-filter/", Description: "Family-friendly DNS service"},
		{ID: "comodo-secure-dns", Name: "Comodo Secure DNS", URL: "https://dns.comodo.com/dns-query", Description: "DNS service with malware protection"},
		{ID: "dnswatch", Name: "DNS.WATCH", URL: "https://dns.watch/dns-query", Description: "No censorship, no filtering, no logging"},
		{ID: "yandex-dns", Name: "Yandex DNS", URL: "https://common.dot.dns.yandex.net", Description: "Russian DNS service with security features"},
		{ID: "uncensoreddns", Name: "UncensoredDNS", URL: "https://unicast.uncensoreddns.org/dns-query", Description: "No filtering, no censorship DNS"},
		{ID: "shecan", Name: "Shecan", URL: "https://free.shecan.ir/dns-query", Description: "Iranian DNS service for bypassing censorship"},
		{ID: "electro", Name: "Electro", URL: "https://dns.electrotm.org/dns-query", Description: "Fast DNS service from Iran"},
		{ID: "yandex-dns-safe", Name: "Yandex DNS Safe", URL: "https://safe.dot.dns.yandex.net", Description: "Russian DNS service with security features"},
		{ID: "yandex-dns-family", Name: "Yandex DNS Family", URL: "https://family.dot.dns.yandex.net", Description: "Russian DNS service with security features"},
		{ID: "opendns-family", Name: "OpenDNS Family", URL: "https://doh.opendns.com/dns-query", Description: "Secure DNS service with content filtering"},
		{ID: "adguard-unfiltered", Name: "AdGuard Unfiltered", URL: "https://unfiltered.adguard-dns.com/dns-query", Description: "Privacy-focused DNS with ad blocking"},
		{ID: "cloudflare-security", Name: "Cloudflare Security", URL: "https://security.cloudflare-dns.com/dns-query", Description: "Fast and private DNS service"},
		{ID: "cloudflare-family", Name: "Cloudflare Family", URL: "https://family.cloudflare-dns.com/dns-query", Description: "Fast and private DNS service"},
		{ID: "cisco-umbrella", Name: "Cisco Umbrella", URL: "https://doh.umbrella.com/dns-query", Description: "Enterprise-grade DNS service with advanced security and threat protection"},
		{ID: "mozilla-dns", Name: "Mozilla DNS", URL: "https://mozilla.cloudflare-dns.com/dns-query", Description: "Privacy-first DNS service operated by Cloudflare under Mozilla's strict privacy policy"},
		{ID: "mullvad-dns", Name: "Mullvad DNS", URL: "https://doh.mullvad.net/dns-query", Description: "Privacy-focused, no-log DNS service operated by Mullvad VPN"},
		{ID: "alidns", Name: "AliDNS", URL: "https://dns.alidns.com/dns-query", Description: "High-performance DNS service operated by Alibaba Cloud"},
		{ID: "dns4eu-unfiltered", Name: "DNS4EU Unfiltered", URL: "https://unfiltered.joindns4.eu/dns-query", Description: "Fast, unfiltered European DNS service with DoH/DoT support"},
		{ID: "dns4eu-protective", Name: "DNS4EU Protective", URL: "https://protective.joindns4.eu/dns-query", Description: "Protective European DNS service with malware and malicious site filtering, DoH/DoT support"},
		{ID: "control-d-free", Name: "Control D (Free)", URL: "https://freedns.controld.com/p0", Description: "DNS service for ad-blocking and enhanced security"},
		{ID: "avast-default", Name: "Avast (Default)", URL: "https://secure.avastdns.com/dns-query", Description: "DNS service focused on ad-blocking and enhanced security"},
		{ID: "comss", Name: "ComSS", URL: "https://dns.comss.one/dns-query", Description: "DNS service focused on ad-blocking and configurable settings"},
		{ID: "nord-dns", Name: "Nord DNS", URL: "https://dns1.nordvpn.com/dns-query", Description: "DNS service from NordVPN focused on ad-blocking and security"},
	}
}

// DNSPreset represents a standard IPv4/IPv6 DNS resolver preset (e.g. for gaming or anti-sanction).
type DNSPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Primary     string `json:"primary"`
	Secondary   string `json:"secondary"`
	Description string `json:"description"`
}

// GetDNSPresets returns the list of popular DNS resolvers, including gaming/anti-sanction presets from Iran (Radar, Zeus, Shecan, etc.).
func GetDNSPresets() []DNSPreset {
	return []DNSPreset{
		{ID: "cloudflare", Name: "Cloudflare", Primary: "1.1.1.1", Secondary: "1.0.0.1", Description: "Fast and private DNS service"},
		{ID: "google-public-dns", Name: "Google Public DNS", Primary: "8.8.8.8", Secondary: "8.8.4.4", Description: "Google's free DNS service"},
		{ID: "opendns", Name: "OpenDNS", Primary: "208.67.222.222", Secondary: "208.67.220.220", Description: "Secure DNS service with content filtering"},
		{ID: "quad9", Name: "Quad9", Primary: "9.9.9.9", Secondary: "149.112.112.112", Description: "Security-focused DNS service"},
		{ID: "adguard-dns", Name: "AdGuard DNS", Primary: "94.140.14.14", Secondary: "94.140.15.15", Description: "Privacy-focused DNS with ad blocking"},
		{ID: "cleanbrowsing", Name: "CleanBrowsing", Primary: "185.228.168.9", Secondary: "185.228.169.9", Description: "Family-friendly DNS service"},
		{ID: "comodo-secure-dns", Name: "Comodo Secure DNS", Primary: "8.26.56.26", Secondary: "8.20.247.20", Description: "DNS service with malware protection"},
		{ID: "verisign-public-dns", Name: "Verisign Public DNS", Primary: "64.6.64.6", Secondary: "64.6.65.6", Description: "Stable and secure DNS service"},
		{ID: "dnswatch", Name: "DNS.WATCH", Primary: "84.200.69.80", Secondary: "84.200.70.40", Description: "No censorship, no filtering, no logging"},
		{ID: "yandex-dns", Name: "Yandex DNS", Primary: "77.88.8.8", Secondary: "77.88.8.1", Description: "Russian DNS service with security features"},
		{ID: "neustar-recursive-dns", Name: "Neustar Recursive DNS", Primary: "156.154.70.1", Secondary: "156.154.71.1", Description: "Enterprise-grade DNS with security"},
		{ID: "safedns", Name: "SafeDNS", Primary: "195.46.39.39", Secondary: "195.46.39.40", Description: "Family protection and content filtering"},
		{ID: "dyn", Name: "Dyn", Primary: "216.146.35.35", Secondary: "216.146.36.36", Description: "Managed DNS and email delivery services"},
		{ID: "freedns", Name: "FreeDNS", Primary: "45.33.97.5", Secondary: "45.33.97.6", Description: "Community-driven DNS service"},
		{ID: "alternate-dns", Name: "Alternate DNS", Primary: "198.101.242.72", Secondary: "23.253.163.53", Description: "Alternative DNS with ad blocking"},
		{ID: "uncensoreddns", Name: "UncensoredDNS", Primary: "91.239.100.100", Secondary: "89.233.43.71", Description: "No filtering, no censorship DNS"},
		{ID: "freenom-world", Name: "Freenom World", Primary: "80.80.80.80", Secondary: "80.80.81.81", Description: "Free DNS service from Freenom"},
		{ID: "opennic", Name: "OpenNIC", Primary: "216.87.84.211", Secondary: "69.164.196.21", Description: "Open, democratic DNS service"},
		{ID: "fourth-estate", Name: "Fourth Estate", Primary: "45.77.165.194", Secondary: "104.238.135.143", Description: "Independent DNS service"},
		{ID: "hurricane-electric", Name: "Hurricane Electric", Primary: "74.82.42.42", Secondary: "66.220.18.42", Description: "IPv6-focused DNS service"},
		{ID: "guifinet", Name: "Guifi.net", Primary: "109.69.8.51", Secondary: "164.138.24.75", Description: "Guifi.net DNS service"},
		{ID: "as20860-dns", Name: "AS20860 DNS", Primary: "87.117.202.100", Secondary: "87.117.202.101", Description: "UK-based DNS service"},
		{ID: "orange-dns", Name: "Orange DNS", Primary: "80.10.246.2", Secondary: "80.10.246.129", Description: "French telecom DNS service"},
		{ID: "tenta-dns", Name: "Tenta DNS", Primary: "99.192.182.100", Secondary: "99.192.182.200", Description: "Privacy-focused DNS with Tor support"},
		{ID: "3dns", Name: "3DNS", Primary: "77.77.77.77", Secondary: "77.77.77.78", Description: "Security-focused DNS service"},
		{ID: "centurylink-dns", Name: "CenturyLink DNS", Primary: "4.2.2.1", Secondary: "4.2.2.2", Description: "DNS service from CenturyLink"},
		{ID: "dns-advantage", Name: "DNS Advantage", Primary: "209.18.47.61", Secondary: "209.18.47.62", Description: "Charter Spectrum DNS service"},
		{ID: "norton-connectsafe", Name: "Norton ConnectSafe", Primary: "199.85.126.10", Secondary: "199.85.127.10", Description: "Security-focused DNS from Norton"},
		{ID: "greenteamdns", Name: "GreenTeamDNS", Primary: "81.218.119.11", Secondary: "209.88.198.133", Description: "Eco-friendly DNS service"},
		{ID: "smartviper", Name: "SmartViper", Primary: "208.76.50.50", Secondary: "208.76.51.51", Description: "Security-focused DNS service"},
		{ID: "dyn-standard-dns", Name: "Dyn Standard DNS", Primary: "216.146.35.35", Secondary: "216.146.36.36", Description: "Standard DNS service from Dyn"},
		{ID: "zerodns", Name: "ZeroDNS", Primary: "199.195.254.10", Secondary: "199.195.254.11", Description: "Minimalist DNS service"},
		{ID: "bitdefender-box", Name: "Bitdefender Box", Primary: "104.16.248.249", Secondary: "104.16.249.249", Description: "Security-focused DNS from Bitdefender"},
		{ID: "shaw-dns", Name: "Shaw DNS", Primary: "64.59.141.70", Secondary: "64.59.141.71", Description: "Canadian ISP DNS service"},
		{ID: "shecan", Name: "Shecan", Primary: "178.22.122.100", Secondary: "185.51.200.2", Description: "Iranian DNS service for bypassing censorship"},
		{ID: "radar-game", Name: "Radar Game", Primary: "10.202.10.10", Secondary: "10.202.10.11", Description: "Gaming-focused DNS service"},
		{ID: "electro", Name: "Electro", Primary: "78.157.42.100", Secondary: "78.157.42.101", Description: "Fast DNS service from Iran"},
		{ID: "yandex-dns-safe", Name: "Yandex DNS Safe", Primary: "77.88.8.88", Secondary: "77.88.8.2", Description: "Russian DNS service with security features"},
		{ID: "yandex-dns-family", Name: "Yandex DNS Family", Primary: "77.88.8.7", Secondary: "77.88.8.3", Description: "Russian DNS service with security features"},
		{ID: "opendns-family", Name: "OpenDNS Family", Primary: "208.67.222.123", Secondary: "208.67.220.123", Description: "Secure DNS service with content filtering"},
		{ID: "adguard-unfiltered", Name: "AdGuard Unfiltered", Primary: "94.140.14.140", Secondary: "94.140.14.141", Description: "Privacy-focused DNS with ad blocking"},
		{ID: "cloudflare-security", Name: "Cloudflare Security", Primary: "1.1.1.2", Secondary: "1.0.0.2", Description: "Fast and private DNS service"},
		{ID: "cloudflare-family", Name: "Cloudflare Family", Primary: "1.1.1.3", Secondary: "1.0.0.3", Description: "Fast and private DNS service"},
		{ID: "cisco-umbrella", Name: "Cisco Umbrella", Primary: "208.67.222.222", Secondary: "208.67.220.220", Description: "Enterprise-grade DNS service with advanced security and threat protection"},
		{ID: "mozilla-dns", Name: "Mozilla DNS", Primary: "104.16.248.249", Secondary: "104.16.249.249", Description: "Privacy-first DNS service operated by Cloudflare under Mozilla's strict privacy policy"},
		{ID: "mullvad-dns", Name: "Mullvad DNS", Primary: "194.242.2.2", Secondary: "194.242.2.3", Description: "Privacy-focused, no-log DNS service operated by Mullvad VPN"},
		{ID: "alidns", Name: "AliDNS", Primary: "223.5.5.5", Secondary: "223.6.6.6", Description: "High-performance DNS service operated by Alibaba Cloud"},
		{ID: "dns4eu-unfiltered", Name: "DNS4EU Unfiltered", Primary: "86.54.11.100", Secondary: "86.54.11.200", Description: "Fast, unfiltered European DNS service with DoH/DoT support"},
		{ID: "dns4eu-protective", Name: "DNS4EU Protective", Primary: "86.54.11.1", Secondary: "86.54.11.201", Description: "Protective European DNS service with malware and malicious site filtering, DoH/DoT support"},
		{ID: "control-d-free", Name: "Control D (Free)", Primary: "76.76.2.0", Secondary: "76.76.10.0", Description: "DNS service for ad-blocking and enhanced security"},
		{ID: "avast-default", Name: "Avast (Default)", Primary: "8.26.56.26", Secondary: "8.20.247.20", Description: "DNS service focused on ad-blocking and enhanced security"},
		{ID: "comss", Name: "ComSS", Primary: "95.217.205.213", Secondary: "", Description: "DNS service focused on ad-blocking and configurable settings"},
		{ID: "nord-dns", Name: "Nord DNS", Primary: "103.86.96.100", Secondary: "103.86.99.100", Description: "DNS service from NordVPN focused on ad-blocking and security"},
	}
}

// ScanPreset represents a scanner configuration profile.
type ScanPreset struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Description         string `json:"description"`
	Concurrency         int    `json:"concurrency"`
	TimeoutMS           int    `json:"timeout_ms"`
	EnableTcp           bool   `json:"enable_tcp"`
	EnableTls           bool   `json:"enable_tls"`
	EnableHttp          bool   `json:"enable_http"`
	EnableTunnel        bool   `json:"enable_tunnel"`
	AdaptiveTimeout     bool   `json:"adaptive_timeout"`
	ConfirmationRequire bool   `json:"confirmation_require"`
}

// GetScanPresets returns the recommended scanner presets.
func GetScanPresets() []ScanPreset {
	return []ScanPreset{
		{
			ID:                  "safe_quick",
			Name:                "Safe Quick",
			Description:         "Conservative visible default, moderate concurrency/rate/jitter, no privileged mutation, explicit targets first.",
			Concurrency:         64,
			TimeoutMS:           2000,
			EnableTcp:           true,
			EnableTls:           true,
			EnableHttp:          false,
			EnableTunnel:        false,
			AdaptiveTimeout:     true,
			ConfirmationRequire: false,
		},
		{
			ID:                  "diagnostic",
			Name:                "Diagnostic",
			Description:         "Local diagnostics and optional public-IP check with clear disclosure of external services contacted.",
			Concurrency:         16,
			TimeoutMS:           4000,
			EnableTcp:           true,
			EnableTls:           true,
			EnableHttp:          true,
			EnableTunnel:        false,
			AdaptiveTimeout:     true,
			ConfirmationRequire: false,
		},
		{
			ID:                  "provider_sample",
			Name:                "Provider Sample",
			Description:         "Bounded provider/corpus sample with requested budget, route/resolver policy, and attribution evidence.",
			Concurrency:         32,
			TimeoutMS:           4000,
			EnableTcp:           true,
			EnableTls:           true,
			EnableHttp:          true,
			EnableTunnel:        false,
			AdaptiveTimeout:     true,
			ConfirmationRequire: false,
		},
		{
			ID:                  "deep_manual",
			Name:                "Deep Manual",
			Description:         "User-confirmed broader scan with visible warnings, estimated duration/data/battery impact, and rate caps.",
			Concurrency:         128,
			TimeoutMS:           5000,
			EnableTcp:           true,
			EnableTls:           true,
			EnableHttp:          true,
			EnableTunnel:        true,
			AdaptiveTimeout:     true,
			ConfirmationRequire: true,
		},
		{
			ID:                  "advanced_transport",
			Name:                "Advanced Transport",
			Description:         "Explicit advanced transport mode, disabled by default, requiring consent, route evidence, provenance, and legal gates.",
			Concurrency:         256,
			TimeoutMS:           5000,
			EnableTcp:           true,
			EnableTls:           true,
			EnableHttp:          true,
			EnableTunnel:        true,
			AdaptiveTimeout:     true,
			ConfirmationRequire: true,
		},
	}
}

// EvasionISPPreset represents the evasion calibration parameters for a specific ISP (MCI, Irancell, TCI).
type EvasionISPPreset struct {
	ISP           string  `json:"isp"`
	NumFragment   int     `json:"num_fragment"`
	FragmentSleep float64 `json:"fragment_sleep"`
	SocketTimeout int     `json:"socket_timeout"`
}

// GetEvasionISPPresets returns the calibration settings .
func GetEvasionISPPresets() []EvasionISPPreset {
	return []EvasionISPPreset{
		{ISP: "mci", NumFragment: 150, FragmentSleep: 0.005, SocketTimeout: 8},
		{ISP: "irancell", NumFragment: 14, FragmentSleep: 0.005, SocketTimeout: 8},
		{ISP: "tci", NumFragment: 200, FragmentSleep: 0.003, SocketTimeout: 8},
		{ISP: "any", NumFragment: 100, FragmentSleep: 0.008, SocketTimeout: 8},
	}
}

// ServerlessRoutingPreset represents a custom direct-routing profile.
type ServerlessRoutingPreset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	FakeDNS     []string `json:"fake_dns"`
	DirectRules []string `json:"direct_rules"`
}

// GetServerlessRoutingPresets returns the custom direct-routing presets.
func GetServerlessRoutingPresets() []ServerlessRoutingPreset {
	return []ServerlessRoutingPreset{
		{
			ID:          "serverless-low-delay",
			Name:        "Serverless Low Delay (Direct)",
			Description: "Optimized direct direct-routing paths for Cloudflare and serverless APIs with fake-DNS mapping.",
			FakeDNS: []string{
				"domain:ir", "geosite:private", "geosite:category-ir", "geosite:xai", "geosite:openai",
				"geosite:google-deepmind", "geosite:anthropic", "geosite:github", "geosite:microsoft",
				"geosite:golang", "geosite:python", "geosite:rust", "full:challenges.cloudflare.com",
			},
			DirectRules: []string{
				"domain:ir", "geosite:private", "geosite:category-ir", "geosite:xai", "geosite:openai",
				"geosite:google-deepmind", "geosite:anthropic", "geosite:github", "geosite:microsoft",
				"geosite:golang", "geosite:python", "geosite:rust",
			},
		},
		{
			ID:          "serverless-high-delay",
			Name:        "Serverless High Delay (Direct)",
			Description: "High-delay direct direct-routing paths for Cloudflare and serverless APIs.",
			FakeDNS: []string{
				"domain:ir", "geosite:private", "geosite:category-ir", "geosite:xai", "geosite:openai",
				"geosite:google-deepmind", "geosite:anthropic", "geosite:github", "geosite:microsoft",
				"geosite:golang", "geosite:python", "geosite:rust", "full:challenges.cloudflare.com",
			},
			DirectRules: []string{
				"domain:ir", "geosite:private", "geosite:category-ir", "geosite:xai", "geosite:openai",
				"geosite:google-deepmind", "geosite:anthropic", "geosite:github", "geosite:microsoft",
				"geosite:golang", "geosite:python", "geosite:rust",
			},
		},
	}
}
