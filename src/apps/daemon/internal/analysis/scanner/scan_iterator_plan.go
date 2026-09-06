// Package scanner — target iterator, scan plan builder, and subnet discovery scanner.
package scanner

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultMaxTargets is the default cap on the number of scan targets.
const DefaultMaxTargets = 10_000

const (
	hardMaxPlanTargets      = 1_000_000
	defaultCandidateFloor   = 4_096
	candidateHostMultiplier = 64
	hardMaxCandidates       = 1_000_000
)

// PortSpec is a list of ports to probe on each host.
type PortSpec []uint16

// CommonPorts is a sane default set for quick scans.
var CommonPorts = PortSpec{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 465,
	587, 993, 995, 1080, 3128, 3306, 5432, 6379,
	8080, 8443, 8888, 9090, 27017,
}

// NmapTop1000Ports is the nmap default port set for comprehensive scans.
var NmapTop1000Ports = PortSpec{
	1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37,
	42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106,
	109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199,
	211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389,
	406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500,
	512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593,
	616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705,
	711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873,
	880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995,
	999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025,
	1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038,
	1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051,
	1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064,
	1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077,
	1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
	1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105,
	1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123,
	1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151,
	1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187,
	1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247,
	1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322,
	1328, 1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503,
	1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688,
	1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805,
	1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972,
	1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
	2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041,
	2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105,
	2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190,
	2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383,
	2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605,
	2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869,
	2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007,
	3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260,
	3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351,
	3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546,
	3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814,
	3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920,
	3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045,
	4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446,
	4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004,
	5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102,
	5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405,
	5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633,
	5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825,
	5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911,
	5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989,
	5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059,
	6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547,
	6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779,
	6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019,
	7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625,
	7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000,
	8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080,
	8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100,
	8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333,
	8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873,
	8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071,
	9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207,
	9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595,
	9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998,
	9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025,
	10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629,
	10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782,
	13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742,
	16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988,
	18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000,
	20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734,
	25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718,
	30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775,
	32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354,
	33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176,
	44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157,
	49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999,
	50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103,
	51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600,
	56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331,
	64623, 64680, 65000, 65129, 65389,
}

// Target is a resolved (host, port) pair ready for probing.
type Target struct {
	Host string
	Port uint16
}

// PlanConfig controls how a ScanPlan is built.
type PlanConfig struct {
	CIDRs      []string
	Hosts      []string
	IPRanges   []string
	Ports      PortSpec
	MaxTargets int
	// MaxCandidates bounds host-candidate evaluation independently of the
	// output target-pair cap. Zero derives a conservative bounded default.
	MaxCandidates int
	Shuffle       bool
	ExcludeCIDRs  []string
}

// ScanPlan is an expanded, deduplicated list of scan targets.
type ScanPlan struct {
	Targets               []Target
	TotalHosts            int
	Truncated             bool
	EvaluatedCandidates   int
	CandidateLimitReached bool
}

// BuildPlan expands configuration into a bounded ScanPlan. The output target
// cap is enforced while source candidates are being enumerated; large CIDRs or
// ranges are never fully materialized merely to discover the first few targets.
func BuildPlan(cfg PlanConfig) (*ScanPlan, error) {
	return buildPlan(cfg, nil)
}

// BuildPlanFromSubnetDivision lazily enumerates parentCIDR at subnetBits and
// feeds usable hosts into the same bounded collector as BuildPlan. It never
// constructs the complete subnet list, so very large IPv6 divisions remain
// safe when MaxTargets is small.
func BuildPlanFromSubnetDivision(parentCIDR string, subnetBits int, cfg PlanConfig) (*ScanPlan, error) {
	return buildPlan(cfg, func(visit func(string) bool) error {
		return walkDividedCIDR(parentCIDR, subnetBits, visit)
	})
}

type hostSourceWalker func(func(string) bool) error

func buildPlan(cfg PlanConfig, prefix hostSourceWalker) (*ScanPlan, error) {
	if cfg.MaxTargets <= 0 {
		cfg.MaxTargets = DefaultMaxTargets
	}
	if cfg.MaxTargets > hardMaxPlanTargets {
		return nil, fmt.Errorf("max targets %d exceeds hard limit %d", cfg.MaxTargets, hardMaxPlanTargets)
	}
	ports := normalizePlanPorts(cfg.Ports)
	if len(ports) == 0 {
		if len(cfg.Ports) > 0 {
			return nil, errors.New("plan contains no valid non-zero ports")
		}
		ports = normalizePlanPorts(CommonPorts)
	}

	var excludeNets []*net.IPNet
	for _, cidr := range cfg.ExcludeCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude CIDR %q: %w", cidr, err)
		}
		excludeNets = append(excludeNets, network)
	}

	maxHosts := (cfg.MaxTargets + len(ports) - 1) / len(ports)
	// One extra accepted host lets us distinguish an exactly-full plan from a
	// source that still had more valid hosts without traversing the universe.
	acceptedHostLimit := maxHosts + 1
	candidateLimit, err := normalizedCandidateLimit(cfg.MaxCandidates, acceptedHostLimit)
	if err != nil {
		return nil, err
	}

	plan := &ScanPlan{}
	seen := make(map[string]struct{}, min(candidateLimit, acceptedHostLimit*candidateHostMultiplier))
	hosts := make([]string, 0, acceptedHostLimit)
	stopped := false

	consider := func(raw string) bool {
		if stopped {
			return false
		}
		if plan.EvaluatedCandidates >= candidateLimit {
			plan.CandidateLimitReached = true
			plan.Truncated = true
			stopped = true
			return false
		}
		plan.EvaluatedCandidates++
		host := strings.TrimSpace(raw)
		if host == "" {
			return true
		}
		if _, exists := seen[host]; exists {
			return true
		}
		seen[host] = struct{}{}
		if ip := net.ParseIP(host); ip != nil {
			for _, network := range excludeNets {
				if network.Contains(ip) {
					return true
				}
			}
		}
		hosts = append(hosts, host)
		if len(hosts) >= acceptedHostLimit {
			plan.Truncated = true
			stopped = true
			return false
		}
		return true
	}

	walk := func(walker hostSourceWalker) error {
		if walker == nil || stopped {
			return nil
		}
		return walker(consider)
	}
	if err := walk(prefix); err != nil {
		return nil, fmt.Errorf("subnet division: %w", err)
	}
	for _, cidr := range cfg.CIDRs {
		if stopped {
			break
		}
		cidr := cidr
		if err := walk(func(visit func(string) bool) error { return walkCIDRPlan(cidr, visit) }); err != nil {
			return nil, fmt.Errorf("CIDR %q: %w", cidr, err)
		}
	}
	for _, rawRange := range cfg.IPRanges {
		if stopped {
			break
		}
		rawRange := rawRange
		if err := walk(func(visit func(string) bool) error { return walkRangePlan(rawRange, visit) }); err != nil {
			return nil, fmt.Errorf("range %q: %w", rawRange, err)
		}
	}
	if !stopped {
		for _, host := range cfg.Hosts {
			if !consider(host) {
				break
			}
		}
	}

	usableHosts := hosts
	if len(usableHosts) > maxHosts {
		usableHosts = usableHosts[:maxHosts]
	}
	plan.TotalHosts = len(usableHosts)
	if cfg.Shuffle && len(usableHosts) > 1 {
		rng, err := cryptoRand()
		if err != nil {
			return nil, fmt.Errorf("shuffle: %w", err)
		}
		rng.Shuffle(len(usableHosts), func(i, j int) { usableHosts[i], usableHosts[j] = usableHosts[j], usableHosts[i] })
	}

	plan.Targets = make([]Target, 0, min(cfg.MaxTargets, len(usableHosts)*len(ports)))
	for hostIndex, host := range usableHosts {
		for portIndex, port := range ports {
			if len(plan.Targets) >= cfg.MaxTargets {
				if hostIndex < len(usableHosts) || portIndex < len(ports) {
					plan.Truncated = true
				}
				return plan, nil
			}
			plan.Targets = append(plan.Targets, Target{Host: host, Port: port})
		}
	}
	if len(hosts) > len(usableHosts) {
		plan.Truncated = true
	}
	return plan, nil
}

func normalizePlanPorts(ports PortSpec) PortSpec {
	seen := make(map[uint16]struct{}, len(ports))
	out := make(PortSpec, 0, len(ports))
	for _, port := range ports {
		if port == 0 {
			continue
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func normalizedCandidateLimit(requested, acceptedHostLimit int) (int, error) {
	if requested < 0 {
		return 0, errors.New("max candidates must not be negative")
	}
	if requested > hardMaxCandidates {
		return 0, fmt.Errorf("max candidates %d exceeds hard limit %d", requested, hardMaxCandidates)
	}
	if requested > 0 {
		return requested, nil
	}
	limit := acceptedHostLimit * candidateHostMultiplier
	if limit < defaultCandidateFloor {
		limit = defaultCandidateFloor
	}
	if limit > hardMaxCandidates {
		limit = hardMaxCandidates
	}
	return limit, nil
}

func walkCIDRPlan(cidr string, visit func(string) bool) error {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	base := ip.Mask(network.Mask)
	if base == nil {
		return fmt.Errorf("invalid CIDR base")
	}
	last := cloneIP(base)
	for index := range last {
		last[index] |= ^network.Mask[index]
	}
	ones, bits := network.Mask.Size()
	skipEdges := bits-ones > 1
	cur := cloneIP(base)
	for network.Contains(cur) {
		isFirst := cur.Equal(base)
		isLast := cur.Equal(last)
		if !(skipEdges && (isFirst || isLast)) {
			if !visit(cur.String()) {
				return nil
			}
		}
		if isLast {
			break
		}
		inc(cur)
	}
	return nil
}

func walkRangePlan(raw string, visit func(string) bool) error {
	parts := strings.SplitN(raw, "-", 2)
	if len(parts) != 2 {
		return errors.New("expected start-end format")
	}
	startText := strings.TrimSpace(parts[0])
	endText := strings.TrimSpace(parts[1])
	start := net.ParseIP(startText).To4()
	if start == nil {
		return fmt.Errorf("invalid start IPv4 address: %s", startText)
	}
	var end net.IP
	if parsed := net.ParseIP(endText).To4(); parsed != nil {
		end = parsed
	} else {
		var lastOctet int
		if _, err := fmt.Sscanf(endText, "%d", &lastOctet); err != nil || lastOctet < 0 || lastOctet > 255 {
			return fmt.Errorf("invalid end value: %s", endText)
		}
		end = net.IPv4(start[0], start[1], start[2], byte(lastOctet)).To4()
	}
	if ipGreater(start, end) {
		return errors.New("start IP is greater than end IP")
	}
	for cur := cloneIP(start); !ipGreater(cur, end); inc(cur) {
		if !visit(cur.String()) {
			return nil
		}
	}
	return nil
}

func walkDividedCIDR(parentCIDR string, subnetBits int, visit func(string) bool) error {
	ip, network, err := net.ParseCIDR(parentCIDR)
	if err != nil {
		return fmt.Errorf("divide CIDR %q: %w", parentCIDR, err)
	}
	ones, bits := network.Mask.Size()
	if subnetBits < ones || subnetBits > bits {
		return fmt.Errorf("subnet bits %d out of range [%d, %d]", subnetBits, ones, bits)
	}
	base := ip.Mask(network.Mask)
	if bits == 32 {
		base = base.To4()
	} else {
		base = base.To16()
	}
	if base == nil {
		return errors.New("invalid parent network")
	}
	baseInt := new(big.Int).SetBytes(base)
	count := new(big.Int).Lsh(big.NewInt(1), uint(subnetBits-ones))
	step := new(big.Int).Lsh(big.NewInt(1), uint(bits-subnetBits))
	one := big.NewInt(1)
	width := bits / 8
	for index := new(big.Int); index.Cmp(count) < 0; index.Add(index, one) {
		offset := new(big.Int).Mul(new(big.Int).Set(index), step)
		value := new(big.Int).Add(baseInt, offset)
		bytes := value.Bytes()
		if len(bytes) < width {
			padded := make([]byte, width)
			copy(padded[width-len(bytes):], bytes)
			bytes = padded
		}
		subnet := fmt.Sprintf("%s/%d", net.IP(bytes).String(), subnetBits)
		keepGoing := true
		if err := walkCIDRPlan(subnet, func(host string) bool {
			keepGoing = visit(host)
			return keepGoing
		}); err != nil {
			return err
		}
		if !keepGoing {
			return nil
		}
	}
	return nil
}

func (p *ScanPlan) Iterate(ctx context.Context) <-chan Target {
	ch := make(chan Target, 64)
	go func() {
		defer close(ch)
		for _, t := range p.Targets {
			select {
			case <-ctx.Done():
				return
			case ch <- t:
			}
		}
	}()
	return ch
}

// ScanTarget defines a host and port set for scanning.
type ScanTarget struct {
	Host  string
	Ports []uint16
}

// HostResult contains open port scan discovery results for a target host.
type HostResult struct {
	Host         string
	OpenPorts    []uint16
	RTT          time.Duration
	Observations []ProbeObservation
}

// SubnetScanner executes parallel TCP port discovery sweeps.
type SubnetScanner struct {
	Timeout     time.Duration
	Concurrency int
	executor    probeExecutor
}

// NewSubnetScanner initializes a SubnetScanner with default 2-second timeout and 50 workers.
func NewSubnetScanner() *SubnetScanner {
	return &SubnetScanner{
		Timeout:     2 * time.Second,
		Concurrency: 50,
		executor:    goProbeExecutor{},
	}
}

// ScanTargets executes parallel port scans across target list.
func (s *SubnetScanner) ScanTargets(ctx context.Context, targets []ScanTarget) []HostResult {
	results := make([]HostResult, 0, len(targets))
	var mu sync.Mutex

	concurrency := s.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

dispatchTargets:
	for _, target := range targets {
		select {
		case <-ctx.Done():
			break dispatchTargets
		case sem <- struct{}{}:
		}
		wg.Add(1)

		go func(t ScanTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			res := s.scanHost(ctx, t)
			if len(res.OpenPorts) > 0 {
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	return results
}

func (s *SubnetScanner) scanHost(ctx context.Context, t ScanTarget) HostResult {
	res := HostResult{Host: t.Host, OpenPorts: make([]uint16, 0), Observations: make([]ProbeObservation, 0, len(t.Ports))}
	start := time.Now()
	executor := s.executor
	if executor == nil {
		executor = goProbeExecutor{}
	}

	for _, port := range t.Ports {
		select {
		case <-ctx.Done():
			return res
		default:
		}

		observation := executor.probe(ctx, probeRequest{
			Endpoint: probeEndpoint{Host: t.Host, Port: port},
			Protocol: probeProtocolTCP,
			Timeout:  s.Timeout,
		})
		res.Observations = append(res.Observations, observation)
		if observation.Succeeded {
			res.OpenPorts = append(res.OpenPorts, port)
		}
	}

	res.RTT = time.Since(start)
	return res
}

// Helpers
func expandCIDRPlan(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string

	// Create a copy of the IP for iteration
	cur := make(net.IP, len(ip.Mask(ipnet.Mask)))
	copy(cur, ip.Mask(ipnet.Mask))

	for ; ipnet.Contains(cur); inc(cur) {
		ips = append(ips, cur.String())
	}
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 1 && len(ips) >= 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func expandRange(r string) ([]string, error) {
	parts := strings.SplitN(r, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("expected start-end format")
	}
	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	start := net.ParseIP(startStr).To4()
	if start == nil {
		return nil, fmt.Errorf("invalid start IPv4 address: %s", startStr)
	}

	var end net.IP
	endFull := net.ParseIP(endStr).To4()
	if endFull != nil {
		end = endFull
	} else {
		var lastOctet int
		if _, err := fmt.Sscanf(endStr, "%d", &lastOctet); err != nil || lastOctet < 0 || lastOctet > 255 {
			return nil, fmt.Errorf("invalid end value: %s", endStr)
		}
		end = net.IPv4(start[0], start[1], start[2], byte(lastOctet))
	}

	if ipGreater(start, end) {
		return nil, fmt.Errorf("start IP is greater than end IP")
	}

	var ips []string
	cur := make(net.IP, len(start))
	copy(cur, start)
	for ; !ipGreater(cur, end); inc(cur) {
		ips = append(ips, cur.String())
	}
	return ips, nil
}

func DeduplicatePorts(ports PortSpec) PortSpec {
	seen := make(map[uint16]bool)
	var result PortSpec
	for _, p := range ports {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func ParsePortRange(spec string) (PortSpec, error) {
	var ports PortSpec
	seen := make(map[uint16]bool)

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			var start, end int
			if _, err := fmt.Sscanf(rangeParts[0], "%d", &start); err != nil {
				return nil, fmt.Errorf("invalid port range start: %s", rangeParts[0])
			}
			if _, err := fmt.Sscanf(rangeParts[1], "%d", &end); err != nil {
				return nil, fmt.Errorf("invalid port range end: %s", rangeParts[1])
			}
			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}
			for p := start; p <= end; p++ {
				if !seen[uint16(p)] {
					seen[uint16(p)] = true
					ports = append(ports, uint16(p))
				}
			}
		} else {
			var p int
			if _, err := fmt.Sscanf(part, "%d", &p); err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of range: %d", p)
			}
			if !seen[uint16(p)] {
				seen[uint16(p)] = true
				ports = append(ports, uint16(p))
			}
		}
	}

	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports, nil
}

func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func ipGreater(a, b net.IP) bool {
	for i := range a {
		if a[i] > b[i] {
			return true
		}
		if a[i] < b[i] {
			return false
		}
	}
	return false
}

func cryptoRand() (*mathrand.Rand, error) {
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	_ = big.NewInt(0)
	src := mathrand.NewSource(int64(binary.LittleEndian.Uint64(seed[:])))
	return mathrand.New(src), nil
}

func ExpandCIDRMax(cidr string, maxIPs int) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for cur := cloneIP(ip.Mask(ipnet.Mask)); ipnet.Contains(cur); inc(cur) {
		ips = append(ips, cur.String())
		if len(ips) >= maxIPs {
			break
		}
	}
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 1 && len(ips) >= 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func SampleCIDR(cidr string, count int) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ones, bits := ipnet.Mask.Size()
	limit := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))

	if bits == 32 && limit.IsInt64() && int64(count) >= limit.Int64() {
		return ExpandCIDRMax(cidr, count)
	}

	seen := make(map[string]bool)
	var ips []string

	baseIP := ip.Mask(ipnet.Mask)
	var baseBytes []byte
	if bits == 32 {
		baseBytes = baseIP.To4()
	} else {
		baseBytes = baseIP.To16()
	}
	baseInt := new(big.Int).SetBytes(baseBytes)

	for len(ips) < count {
		offset, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}

		ipInt := new(big.Int).Add(baseInt, offset)
		ipBytes := ipInt.Bytes()

		padLen := bits / 8
		if len(ipBytes) < padLen {
			pad := make([]byte, padLen-len(ipBytes))
			ipBytes = append(pad, ipBytes...)
		}

		ipStr := net.IP(ipBytes).String()
		if !seen[ipStr] {
			seen[ipStr] = true
			ips = append(ips, ipStr)
		}
	}

	return ips, nil
}
