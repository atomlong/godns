package cloudflare

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/TimothyYe/godns/notify"

	"github.com/TimothyYe/godns"
)

// Handler struct definition
type Handler struct {
	Configuration *godns.Settings
	API           string
}

// DNSRecordResponse struct
type DNSRecordResponse struct {
	Records []DNSRecord `json:"result"`
	Success bool        `json:"success"`
}

// DNSRecordUpdateResponse struct
type DNSRecordUpdateResponse struct {
	Record  DNSRecord `json:"result"`
	Success bool      `json:"success"`
}

// DNSRecord for Cloudflare API
type DNSRecord struct {
	ID      string `json:"id"`
	IP      string `json:"content"`
	Name    string `json:"name"`
	Proxied bool   `json:"proxied"`
	Type    string `json:"type"`
	ZoneID  string `json:"zone_id"`
	TTL     int32  `json:"ttl"`
}

// SetIP updates DNSRecord.IP
func (r *DNSRecord) SetIP(ip string) {
	r.IP = ip
}

// ZoneResponse is a wrapper for Zones
type ZoneResponse struct {
	Zones   []Zone `json:"result"`
	Success bool   `json:"success"`
}

// Zone object with id and name
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// SetConfiguration pass dns settings and store it to handler instance
func (handler *Handler) SetConfiguration(conf *godns.Settings) {
	handler.Configuration = conf
	handler.API = "https://api.cloudflare.com/client/v4"
}

// DomainLoop the main logic loop
func (handler *Handler) DomainLoop(domain *godns.Domain, panicChan chan<- godns.Domain) {
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("Recovered in %v: %v\n", err, string(debug.Stack()))
			panicChan <- *domain
		}
	}()

	var lastIP string
	looping := false
	for {
		if looping {
			// Sleep with interval
			log.Debugf("Going to sleep, will start next checking in %d seconds...\r\n", handler.Configuration.Interval)
			time.Sleep(time.Second * time.Duration(handler.Configuration.Interval))
		}
		looping = true

		currentIP, err := godns.GetCurrentIP(handler.Configuration)
		if err != nil {
			log.Error("Error in GetCurrentIP:", err)
			continue
		}
		log.Debug("Current IP is:", currentIP)
		//check against locally cached IP, if no change, skip update
		if currentIP == lastIP {
			log.Infof("IP is the same as cached one (%s). Skip update.\n", currentIP)
		} else {
			log.Info("Checking IP for domain ", domain.DomainName)
			zoneID := handler.getZone(domain.DomainName)
			if zoneID != "" {
				records := handler.getDNSRecords(zoneID)

				// add records
				for _, subDomain := range domain.SubDomains {
					if subDomain[0] == '-' {
						continue
					}
					if !subDomainTracked(subDomain, domain.DomainName, &records) {
						sd := fmt.Sprintf("%s.%s", subDomain, domain.DomainName)
						newRecord := DNSRecord{
							Type:    "A",
							Name:    sd,
							IP:      currentIP,
							TTL:     1,
							Proxied: true,
							ZoneID:  zoneID,
						}
						if err := handler.addRecord(newRecord); err != nil {
							log.Infof("Failed to update IP for subdomain:%s\r\n", subDomain)
						} else {
							log.Infof("Record added for subdomain:%s\r\n", subDomain)
						}
					}
				}

				// update or delete records
				for _, rec := range records {

					tracked, del := recordTracked(domain, &rec)
					if !tracked {
						log.Debug("Skiping record:", rec.Name)
						continue
					}
					if del {
						if handler.deleteRecord(rec) == nil {
							log.Infof("Record Deleted: %s\r\n", rec.Name)
							for index, subDomain := range domain.SubDomains {
								if subDomain[0] == '-' {
									subDomain = strings.TrimLeft(subDomain, "-")
								}
								sd := fmt.Sprintf("%s.%s", subDomain, domain.DomainName)
								if rec.Name == sd || (subDomain == godns.RootDomain && rec.Name == domain.DomainName) {
									godns.ArrayRemoveItem(&domain.SubDomains, index)
									break
								}
							}
						}
						continue
					}
					if rec.IP != currentIP {
						log.Infof("IP mismatch: Current(%+v) vs Cloudflare(%+v)\r\n", currentIP, rec.IP)
						lastIP = handler.updateRecord(rec, currentIP)

						// Send notification
						notify.GetNotifyManager(handler.Configuration).Send(rec.Name, currentIP)
					} else {
						log.Infof("Record OK: %+v - %+v\r\n", rec.Name, rec.IP)
					}
				}
			} else {
				log.Info("Failed to find zone for domain:", domain.DomainName)
			}
		}
	}
}

// Check if record is present in domain conf
func recordTracked(domain *godns.Domain, record *DNSRecord) (bool, bool) {
	del := false
	for _, subDomain := range domain.SubDomains {
		if subDomain[0] == '-' {
			del = true
			subDomain = strings.TrimLeft(subDomain, "-")
		}
		sd := fmt.Sprintf("%s.%s", subDomain, domain.DomainName)
		if record.Name == sd {
			return true, del
		} else if subDomain == godns.RootDomain && record.Name == domain.DomainName {
			return true, del
		}
	}

	return false, del
}

// Check if subDomain is present in records
func subDomainTracked(subDomain string, domainName string, records *[]DNSRecord) bool {
	sd := fmt.Sprintf("%s.%s", subDomain, domainName)
	for _, rec := range *records {
		if rec.Name == sd {
			return true
		} else if subDomain == godns.RootDomain && rec.Name == domainName {
			return true
		}
	}

	return false
}

// Create a new request with auth in place and optional proxy
func (handler *Handler) newRequest(method, url string, body io.Reader) (*http.Request, *http.Client) {
	client := godns.GetHttpClient(handler.Configuration, handler.Configuration.UseProxy)
	if client == nil {
		log.Info("cannot create HTTP client")
	}

	req, _ := http.NewRequest(method, handler.API+url, body)
	req.Header.Set("Content-Type", "application/json")

	if handler.Configuration.Email != "" && handler.Configuration.Password != "" {
		req.Header.Set("X-Auth-Email", handler.Configuration.Email)
		req.Header.Set("X-Auth-Key", handler.Configuration.Password)
	} else if handler.Configuration.LoginToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", handler.Configuration.LoginToken))
	}

	return req, client
}

// Find the correct zone via domain name
func (handler *Handler) getZone(domain string) string {

	var z ZoneResponse

	req, client := handler.newRequest("GET", fmt.Sprintf("/zones?name=%s", domain), nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Request error:", err)
		return ""
	}

	body, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(body, &z)
	if err != nil {
		log.Errorf("Decoder error: %+v\n", err)
		log.Debugf("Response body: %+v\n", string(body))
		return ""
	}
	if z.Success != true {
		log.Infof("Response failed: %+v\n", string(body))
		return ""
	}

	for _, zone := range z.Zones {
		if zone.Name == domain {
			return zone.ID
		}
	}
	return ""
}

// Get all DNS A records for a zone
func (handler *Handler) getDNSRecords(zoneID string) []DNSRecord {

	var empty []DNSRecord
	var r DNSRecordResponse
	var recordType string

	if handler.Configuration.IPType == "" || strings.ToUpper(handler.Configuration.IPType) == godns.IPV4 {
		recordType = godns.IPTypeA
	} else if strings.ToUpper(handler.Configuration.IPType) == godns.IPV6 {
		recordType = godns.IPTypeAAAA
	}

	log.Info("Querying records with type:", recordType)
	req, client := handler.newRequest("GET", fmt.Sprintf("/zones/"+zoneID+"/dns_records?type=%s&page=1&per_page=500", recordType), nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Request error:", err)
		return empty
	}

	body, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(body, &r)
	if err != nil {
		log.Infof("Decoder error: %+v\n", err)
		log.Debugf("Response body: %+v\n", string(body))
		return empty
	}
	if r.Success != true {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Infof("Response failed: %+v\n", string(body))
		return empty

	}
	return r.Records
}

// Add DNS A Record
func (handler *Handler) addRecord(record DNSRecord) error {
	var r DNSRecordUpdateResponse

	j, _ := json.Marshal(record)
	req, client := handler.newRequest("POST",
		"/zones/"+record.ZoneID+"/dns_records",
		bytes.NewBuffer(j),
	)

	resp, err := client.Do(req)
	if err != nil {
		log.Error("Request error:", err)
		return err
	}

	body, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(body, &r)
	if err != nil {
		log.Errorf("Decoder error: %+v\n", err)
		log.Debugf("Response body: %+v\n", string(body))
		return err
	}
	if !r.Success {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Infof("Response failed: %+v \n", string(body))
		return errors.New("Failed")
	} else {
		log.Infof("Record updated: %+v - %+v", record.Name, record.IP)
	}

	return nil
}

// Delete DNS A Record
func (handler *Handler) deleteRecord(record DNSRecord) error {
	var r DNSRecordUpdateResponse

	j, _ := json.Marshal(record)
	req, client := handler.newRequest("DELETE",
		"/zones/"+record.ZoneID+"/dns_records/"+record.ID,
		bytes.NewBuffer(j),
	)
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Request error:", err)
		return err
	}

	body, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(body, &r)
	if err != nil {
		log.Errorf("Decoder error: %+v\n", err)
		log.Debugf("Response body: %+v\n", string(body))
		return err
	}
	if !r.Success {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Infof("Response failed: %+v\n", string(body))
		return errors.New("Failed")
	} else {
		log.Infof("Record updated: %+v - %+v", record.Name, record.IP)
	}

	return nil
}

// Update DNS A Record with new IP
func (handler *Handler) updateRecord(record DNSRecord, newIP string) string {

	var r DNSRecordUpdateResponse
	record.SetIP(newIP)
	var lastIP string

	j, _ := json.Marshal(record)
	req, client := handler.newRequest("PUT",
		"/zones/"+record.ZoneID+"/dns_records/"+record.ID,
		bytes.NewBuffer(j),
	)
	resp, err := client.Do(req)
	if err != nil {
		log.Error("Request error:", err)
		return ""
	}

	body, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(body, &r)
	if err != nil {
		log.Errorf("Decoder error: %+v\n", err)
		log.Debugf("Response body: %+v\n", string(body))
		return ""
	}
	if r.Success != true {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Infof("Response failed: %+v\n", string(body))
	} else {
		log.Infof("Record updated: %+v - %+v", record.Name, record.IP)
		lastIP = record.IP
	}
	return lastIP
}
