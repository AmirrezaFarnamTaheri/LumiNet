package dns

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPackCatalogLoadsRealFiletag(t *testing.T) {
	path := filepath.Join("testdata", "filetag.json")
	catalog, err := LoadPackCatalog(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Tags) < 100 {
		t.Fatalf("expected a large catalog, got %d tags", len(catalog.Tags))
	}
	packs := catalog.Packs()
	if len(packs) == 0 {
		t.Fatal("no packs discovered")
	}
	for _, pack := range packs {
		urls := catalog.URLs(pack)
		for _, u := range urls {
			if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				t.Errorf("unexpected url scheme in pack %s: %s", pack, u)
			}
		}
	}
}

func TestTagsForPackFiltering(t *testing.T) {
	data := []byte(`{
	  "171": {"value":171,"uname":"171","vname":"1Hosts (Xtra)","group":"privacy","url":"https://a/x","format":"domains","pack":["extremeprivacy"],"level":[2],"entries":10},
	  "172": {"value":172,"uname":"172","vname":"Other","group":"ads","url":"https://b/y","format":"domains","pack":["light"],"level":[1],"entries":5}
	}`)
	catalog, err := ParsePackCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	xtra := catalog.TagsForPack("ExtremePrivacy") // case-insensitive
	if len(xtra) != 1 || xtra[0].VName != "1Hosts (Xtra)" {
		t.Fatalf("pack filter wrong: %+v", xtra)
	}
	if urls := catalog.URLs("light"); len(urls) != 1 || urls[0] != "https://b/y" {
		t.Fatalf("urls wrong: %v", urls)
	}
}

func TestParsePackCatalogRejectsBadDocs(t *testing.T) {
	if _, err := ParsePackCatalog([]byte(`{}`)); err == nil {
		t.Fatal("empty catalog must be rejected")
	}
	if _, err := ParsePackCatalog([]byte(`{"9":{"vname":"no url"}}`)); err == nil {
		t.Fatal("tag without url must be rejected")
	}
	if _, err := ParsePackCatalog([]byte(`not json`)); err == nil {
		t.Fatal("garbage must be rejected")
	}
}
