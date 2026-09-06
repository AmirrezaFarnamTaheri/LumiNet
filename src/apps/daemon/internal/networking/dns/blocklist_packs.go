// Blocklist pack/tag catalog .json model
// (MPL-2, data format preserved; loader re-expressed).
//
// A "tag" identifies one upstream blocklist (URL + format + entry count). Tags
// are grouped into named packs ("extremeprivacy", …) and carry severity
// levels, letting operators subscribe to a pack while the engine resolves the
// concrete list URLs.
package dns

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// BlocklistTag describes one upstream blocklist.
type BlocklistTag struct {
	Value   int         `json:"value"`
	UName   string      `json:"uname"`
	VName   string      `json:"vname"`
	Group   string      `json:"group"`
	Subg    string      `json:"subg,omitempty"`
	URL     string      `json:"url"`
	Format  StringList  `json:"format"`
	Packs   []string    `json:"pack"`
	Levels  []int       `json:"level"`
	Entries int         `json:"entries"`
}

// StringList tolerates filetag entries that encode a field either as a bare
// string or as an array of strings.
type StringList []string

// UnmarshalJSON accepts both forms.
func (s *StringList) UnmarshalJSON(data []byte) error {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var single string
		if err := json.Unmarshal(data, &single); err != nil {
			return err
		}
		*s = []string{single}
		return nil
	}
	var list []string
	return json.Unmarshal(data, &list)
}

// First returns the first entry or "" when empty.
func (s StringList) First() string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// PackCatalog indexes tags by id and exposes pack/group lookups.
type PackCatalog struct {
	Tags map[int]BlocklistTag `json:"tags"`
	// Skipped lists ids dropped during parse (e.g. upstream entries with no
	// list URL); kept visible so callers can account for the difference.
	Skipped []int `json:"skipped,omitempty"`
}

// LoadPackCatalog reads a filetag.json document from disk.
func LoadPackCatalog(path string) (*PackCatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pack catalog: %w", err)
	}
	return ParsePackCatalog(data)
}

// ParsePackCatalog decodes a filetag.json document.
func ParsePackCatalog(data []byte) (*PackCatalog, error) {
	var raw map[string]BlocklistTag
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse pack catalog: %w", err)
	}
	catalog := &PackCatalog{Tags: make(map[int]BlocklistTag, len(raw))}
	for key, tag := range raw {
		id, idErr := strconv.Atoi(key)
		if idErr != nil {
			// Some upstream revisions encode ids in base36 ("MTF").
			v, perr := strconv.ParseInt(strings.ToLower(key), 36, 32)
			if perr != nil {
				catalog.Skipped = append(catalog.Skipped, -1)
				continue
			}
			id = int(v)
		}
		if tag.Value == 0 {
			tag.Value = id
		}
		if strings.TrimSpace(tag.URL) == "" {
			// Upstream ships occasional metadata-only tags (no list URL);
			// skipping keeps the rest of the catalog usable.
			catalog.Skipped = append(catalog.Skipped, tag.Value)
			continue
		}
		catalog.Tags[tag.Value] = tag
	}
	if len(catalog.Tags) == 0 {
		return nil, fmt.Errorf("pack catalog is empty")
	}
	return catalog, nil
}

// TagsForPack returns every tag belonging to a pack, sorted by name.
func (c *PackCatalog) TagsForPack(pack string) []BlocklistTag {
	out := make([]BlocklistTag, 0)
	for _, tag := range c.Tags {
		for _, p := range tag.Packs {
			if strings.EqualFold(p, pack) {
				out = append(out, tag)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VName < out[j].VName })
	return out
}

// Packs lists distinct pack names sorted alphabetically.
func (c *PackCatalog) Packs() []string {
	set := map[string]struct{}{}
	for _, tag := range c.Tags {
		for _, p := range tag.Packs {
			set[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// URLs returns each tag's list URL for the given pack in stable order.
func (c *PackCatalog) URLs(pack string) []string {
	tags := c.TagsForPack(pack)
	urls := make([]string, 0, len(tags))
	for _, t := range tags {
		urls = append(urls, t.URL)
	}
	return urls
}
