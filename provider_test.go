package googleclouddns

import (
	"context"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"google.golang.org/api/googleapi"
)

var (
	testProject = `test-dev`
	testZone    = `libdns.io.`
)

func Test_GetRecords(t *testing.T) {
	p, rs, err := getTestDNSClient(`./replay/provider_getrecords.json`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	t.Run("retrieve existing records", func(t *testing.T) {
		expectedTXTRecordValue := `Hi there! This is a TXT record!`
		p.Project = testProject
		records, err := p.GetRecords(context.Background(), testZone)
		if err != nil {
			t.Fatal("error listing records from the test zone:", err)
		}
		if len(records) != 6 {
			t.Fatal("expected six records back, received", len(records))
		}
		for _, record := range records {
			rr := record.RR()
			if rr.Type != "TXT" && rr.Name != "hello" {
				continue
			}
			if rr.Data != expectedTXTRecordValue {
				t.Fatalf("Expected TXT record '%s', received '%s'", expectedTXTRecordValue, rr.Data)
			}
		}
	})
	t.Run("attempt to request non-existent zone", func(t *testing.T) {
		p.Project = testProject
		records, err := p.GetRecords(context.Background(), `i-do-not-exist.io.`)
		if err == nil {
			t.Fatal("expected an error back but did not receive one")
		}
		if records != nil {
			t.Fatal("there were records returned for a non-existent zone")
		}
	})
}

func Test_AppendRecords(t *testing.T) {
	p, rs, err := getTestDNSClient(`./replay/provider_appendrecords.json`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	recordsToAppend := []libdns.Record{
		libdns.RR{
			Type: "TXT",
			Name: "caddy-validation",
			Data: `I SHOULD NOT HAVE EXTRA QUOTES`,
			TTL:  time.Minute,
		},
		libdns.RR{
			Type: "TXT",
			Name: "caddy-validation",
			Data: `1234567890abcdef`,
			TTL:  time.Minute,
		},
		libdns.RR{
			Type: "A",
			Name: "www",
			Data: "127.0.0.1",
			TTL:  time.Minute * 5,
		},
	}
	t.Run("appending creates new records", func(t *testing.T) {
		p.Project = testProject

		records, err := p.AppendRecords(context.Background(), testZone, recordsToAppend)
		if err != nil {
			t.Fatal("error appending new records to the DNS zone:", err)
		}
		if len(records) != 3 {
			t.Fatal("expected three records back, received", len(records))
		}
		compareTestData(recordsToAppend, records, t)
		txtRecords, err := p.getCloudDNSRecord(context.Background(), testZone, `caddy-validation`, `TXT`)
		if err != nil {
			t.Fatal("error retrieving TXT record for comparison", err)
		}
		compareTestData(recordsToAppend[:2], txtRecords, t)
		aRecord, err := p.getCloudDNSRecord(context.Background(), testZone, `www`, `A`)
		if err != nil {
			t.Fatal("error retrieving A record for comparison", err)
		}
		compareTestData(recordsToAppend[2:], aRecord, t)
	})

	t.Run("appending creates new entries on existing records", func(t *testing.T) {
		p.Project = testProject
		recordsToAppend := []libdns.Record{
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation",
				Data: `I provide new information to the cloud`,
				TTL:  time.Minute,
			},
		}
		records, err := p.AppendRecords(context.Background(), testZone, recordsToAppend)
		if err != nil {
			t.Fatal("error appending a new record to an existing DNS entry:", err)
		}
		if len(records) != 1 {
			t.Fatal("expected one record back, received", len(records))
		}
		compareTestData(recordsToAppend, records, t)
		txtRecords, err := p.getCloudDNSRecord(context.Background(), testZone, `caddy-validation`, `TXT`)
		if err != nil {
			t.Fatal("error retrieving TXT record for comparison", err)
		}
		fullRecord := append(recordsToAppend, libdns.RR{
			Type: "TXT",
			Name: "caddy-validation",
			Data: `I provide new information to the cloud`,
			TTL:  time.Minute,
		},
		)
		compareTestData(fullRecord, txtRecords, t)
	})

	t.Run("appending returns no records where entries exist in existing Cloud DNS entry", func(t *testing.T) {
		p.Project = testProject
		recordsToAppend := []libdns.Record{
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation",
				Data: `I provide new information to the cloud`,
				TTL:  time.Minute,
			},
		}
		records, err := p.AppendRecords(context.Background(), testZone, recordsToAppend)
		if err != nil {
			t.Fatal("received an error when attempting to add an already existing record")
		}
		if len(records) != 0 {
			t.Fatal("expected no records back, received", len(records))
		}
		txtRecords, err := p.getCloudDNSRecord(context.Background(), testZone, `caddy-validation`, `TXT`)
		if err != nil {
			t.Fatal("error retrieving TXT record for comparison", err)
		}
		if len(txtRecords) != 3 {
			t.Fatal("Should received 3 records back for TXT entry but received", len(txtRecords))
		}
	})
}

func Test_SetRecords(t *testing.T) {
	p, rs, err := getTestDNSClient(`./replay/provider_setrecords.json`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	t.Run("setting creates new records", func(t *testing.T) {
		p.Project = testProject
		recordsToCreate := []libdns.Record{
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation-mark2",
				Data: `I SHOULD NOT HAVE EXTRA QUOTES`,
				TTL:  time.Minute,
			},
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation-mark2",
				Data: `1234567890abcdef`,
				TTL:  time.Minute,
			},
		}
		records, err := p.SetRecords(context.Background(), testZone, recordsToCreate)
		if err != nil {
			t.Fatal("error setting new records to the DNS zone:", err)
		}
		if len(records) != 2 {
			t.Fatal("expected two records back, received", len(records))
		}
		compareTestData(recordsToCreate, records, t)
		txtRecords, err := p.getCloudDNSRecord(context.Background(), testZone, `caddy-validation-mark2`, `TXT`)
		if err != nil {
			t.Fatal("error retrieving TXT record for comparison", err)
		}
		compareTestData(recordsToCreate, txtRecords, t)
	})

	t.Run("setting overwrites existing records", func(t *testing.T) {
		p.Project = testProject
		recordToOverwrite := []libdns.Record{
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation-mark2",
				Data: `I provide new information to the cloud`,
				TTL:  time.Minute,
			},
		}
		records, err := p.SetRecords(context.Background(), testZone, recordToOverwrite)
		if err != nil {
			t.Fatal("error appending a new record to an existing DNS entry:", err)
		}
		if len(records) != 1 {
			t.Fatal("expected one record back, received", len(records))
		}
		compareTestData(recordToOverwrite, records, t)
		txtRecords, err := p.getCloudDNSRecord(context.Background(), testZone, `caddy-validation-mark2`, `TXT`)
		if err != nil {
			t.Fatal("error retrieving TXT record for comparison", err)
		}
		compareTestData(recordToOverwrite, txtRecords, t)
	})
}

func Test_DeleteRecords(t *testing.T) {
	p, rs, err := getTestDNSClient(`./replay/provider_deleterecords.json`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	t.Run("delete entire record", func(t *testing.T) {
		p.Project = testProject
		recordToDelete := []libdns.Record{
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation-mark2",
				Data: `I provide new information to the cloud`,
				TTL:  time.Minute,
			},
		}
		records, err := p.DeleteRecords(context.Background(), testZone, recordToDelete)
		if err != nil {
			t.Fatal("error setting new records to the DNS zone:", err)
		}
		if len(records) != 1 {
			t.Fatal("expected one record back, received", len(records))
		}
		if len(records) == 1 && (records[0].RR().Name != recordToDelete[0].RR().Name || records[0].RR().Data != recordToDelete[0].RR().Data) {
			t.Fatalf("The record submitted, %v, does not match the record received %v", recordToDelete[0], records[0])
		}
	})

	t.Run("deletes a single record from a multi record entry", func(t *testing.T) {
		p.Project = testProject
		recordToDelete := []libdns.Record{
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation",
				Data: `I SHOULD NOT HAVE EXTRA QUOTES`,
				TTL:  time.Minute,
			},
		}
		recordCleaned := []libdns.Record{
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation",
				Data: `I provide new information to the cloud`,
				TTL:  time.Minute,
			},
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation",
				Data: `1234567890abcdef`,
				TTL:  time.Minute,
			},
		}
		records, err := p.DeleteRecords(context.Background(), testZone, recordToDelete)
		if err != nil {
			t.Fatal("error deleting a single record from an existing DNS entry:", err)
		}
		if len(records) != 1 {
			t.Fatal("expected one record back, received", len(records))
		}
		compareTestData(recordToDelete, records, t)
		txtRecords, err := p.getCloudDNSRecord(context.Background(), testZone, `caddy-validation`, `TXT`)
		if err != nil {
			t.Fatal("error retrieving TXT record for comparison", err)
		}
		compareTestData(recordCleaned, txtRecords, t)
	})

	t.Run("deletes no records when a non-existent one is specified", func(t *testing.T) {
		p.Project = testProject
		recordToDelete := []libdns.Record{
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation",
				Data: `I SHOULD NOT HAVE EXTRA QUOTES`,
				TTL:  time.Minute,
			},
		}
		recordCleaned := []libdns.Record{
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation",
				Data: `I provide new information to the cloud`,
				TTL:  time.Minute,
			},
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation",
				Data: `1234567890abcdef`,
				TTL:  time.Minute,
			},
		}
		records, err := p.DeleteRecords(context.Background(), testZone, recordToDelete)
		if err != nil {
			t.Fatal("error attempting to delete a non-existent record:", err)
		}
		if len(records) != 0 {
			t.Fatal("expected no records back, received", len(records))
		}
		txtRecords, err := p.getCloudDNSRecord(context.Background(), testZone, `caddy-validation`, `TXT`)
		if err != nil {
			t.Fatal("error retrieving TXT record for comparison", err)
		}
		compareTestData(recordCleaned, txtRecords, t)
	})

	t.Run("deletes one record when two are specified", func(t *testing.T) {
		p.Project = testProject
		recordToDelete := []libdns.Record{
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation",
				Data: `I SHOULD NOT HAVE EXTRA QUOTES`,
				TTL:  time.Minute,
			},
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation",
				Data: `I provide new information to the cloud`,
				TTL:  time.Minute,
			},
		}
		recordCleaned := []libdns.Record{
			libdns.RR{
				Type: "TXT",
				Name: "caddy-validation",
				Data: `1234567890abcdef`,
				TTL:  time.Minute,
			},
		}
		records, err := p.DeleteRecords(context.Background(), testZone, recordToDelete)
		if err != nil {
			t.Fatal("error attempting to delete record:", err)
		}
		if len(records) != 1 {
			t.Fatal("expected one record back, received", len(records))
		}
		compareTestData(recordToDelete[1:], records, t)
		txtRecords, err := p.getCloudDNSRecord(context.Background(), testZone, `caddy-validation`, `TXT`)
		if err != nil {
			t.Fatal("error retrieving TXT record for comparison", err)
		}
		compareTestData(recordCleaned, txtRecords, t)
	})
}

func Test_EndToEnd(t *testing.T) {
	p, rs, err := getTestDNSClient(`./replay/provider_endtoendrecords.json`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	p.Project = testProject
	requestOne := []libdns.Record{
		libdns.RR{
			Type: "TXT",
			Name: "_acme-challenge",
			Data: `1234567890abcdef`,
			TTL:  0,
		},
	}
	requestTwo := []libdns.Record{
		libdns.RR{
			Type: "TXT",
			Name: "_acme-challenge",
			Data: `fedcba0987654321`,
			TTL:  0,
		},
	}
	appendedRecords, err := p.AppendRecords(context.Background(), testZone, requestOne)
	if err != nil {
		t.Fatal("error setting up first challenge:", err)
	}
	compareTestData(requestOne, appendedRecords, t)

	appendedRecords, err = p.AppendRecords(context.Background(), testZone, requestTwo)
	if err != nil {
		t.Fatal("error setting up second challenge:", err)
	}
	compareTestData(requestTwo, appendedRecords, t)

	txtRecords, err := p.getCloudDNSRecord(context.Background(), testZone, `_acme-challenge`, `TXT`)
	if err != nil {
		t.Fatal("error retrieving TXT record for comparison", err)
	}
	if len(txtRecords) != 2 {
		t.Fatal("expectd there to be two records but received", len(txtRecords))
	}

	deletedRecord, err := p.DeleteRecords(context.Background(), testZone, requestTwo)
	if err != nil {
		t.Fatal("error deleting single record from Cloud DNS entry", err)
	}
	if len(deletedRecord) != 1 {
		t.Fatal("expected 1 record back but received", len(deletedRecord))
	}

	txtRecords, err = p.getCloudDNSRecord(context.Background(), testZone, `_acme-challenge`, `TXT`)
	if err != nil {
		t.Fatal("error retrieving TXT record for comparison", err)
	}
	if len(txtRecords) != 1 {
		t.Fatal("expectd there to be on record but received", len(txtRecords))
	}

	deletedRecord, err = p.DeleteRecords(context.Background(), testZone, requestOne)
	if err != nil {
		t.Fatal("error deleting single record from Cloud DNS entry", err)
	}
	if len(deletedRecord) != 1 {
		t.Fatal("expected 1 record back but received", len(deletedRecord))
	}

	txtRecords, err = p.getCloudDNSRecord(context.Background(), testZone, `_acme-challenge`, `TXT`)
	if err != nil {
		if googleError, ok := err.(*googleapi.Error); !ok || (ok && googleError.Code != 404) {
			t.Fatal("error retrieving TXT record for comparison", err)
		}
	}
	if len(txtRecords) != 0 {
		t.Fatal("expectd there to be no records received but received", len(txtRecords))
	}
}
