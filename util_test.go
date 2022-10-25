package googleclouddns

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/httpreplay"
	"github.com/libdns/libdns"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

func compareTestData(test, results []libdns.Record, t *testing.T) {
	for _, testEntry := range test {
		foundResult := false
		for _, resultEntry := range results {
			if testEntry == resultEntry {
				foundResult = true
			}
		}
		if !foundResult {
			for _, result := range results {
				t.Logf("%+v", result)
			}
			t.Fatalf("Did not find a result for entry %+v", testEntry)
		}
	}
}

type replayClose interface {
	Close() error
}

// getTestDNSClient returns a Client prepped for testing. If the replay
// file exists in the replay folder, it will use that for testing,
// otherwise it will do a live request
func getTestDNSClient(filename string) (*Provider, replayClose, error) {
	var client *http.Client
	var rs replayClose
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		// Setup recorder and write out to specified filename
		client, rs, err = setupRecorder(filename)
	} else {
		// Playback file exists, use that to run tests
		client, rs, err = setupPlayback(filename)
	}
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	scopeOption := option.WithScopes(dns.NdevClouddnsReadwriteScope)
	httpClientOption := option.WithHTTPClient(client)
	dnsService, err := dns.NewService(ctx, scopeOption, httpClientOption)
	if err != nil {
		return nil, nil, err
	}
	provider := Provider{
		service: dnsService,
	}
	return &provider, rs, err
}

func setupRecorder(filename string) (*http.Client, replayClose, error) {
	ctx := context.Background()
	now := time.Now().UTC()
	nowBytes, err := json.Marshal(now)
	if err != nil {
		return nil, nil, err
	}
	tokenSource, err := google.DefaultTokenSource(ctx, dns.NdevClouddnsReadwriteScope)
	if err != nil {
		return nil, nil, err
	}
	rec, err := httpreplay.NewRecorder(filename, nowBytes)
	if err != nil {
		return nil, nil, err
	}
	opt := option.WithTokenSource(tokenSource)
	resClient, err := rec.Client(ctx, opt)
	if err != nil {
		return nil, nil, err
	}
	return resClient, rec, nil
}

func setupPlayback(filename string) (*http.Client, replayClose, error) {
	ctx := context.Background()
	replayer, err := httpreplay.NewReplayer(filename)
	if err != nil {
		return nil, nil, err
	}
	var tm time.Time
	if err := json.Unmarshal(replayer.Initial(), &tm); err != nil {
		return nil, nil, err
	}
	resClient, err := replayer.Client(ctx)
	if err != nil {
		return nil, nil, err
	}
	return resClient, replayer, nil
}
