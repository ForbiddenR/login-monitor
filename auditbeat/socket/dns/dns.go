package dns

import (
	"context"
	"net"

	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/pkg/errors"
)

// Transaction represents a DNS transaction of A or AAAA type.
type Transaction struct {
	// TXID the transaction ID.
	TXID uint16

	// Client is the address of the client side of the transaction
	Client net.UDPAddr

	// Server is the address of the DNS server.
	Server net.UDPAddr

	// Domain is the name queried by the client.
	Domain string

	// Addresses is the list of A or AAAA address in the reponse.
	Addresses []net.IP
}

// Consumer is a function that consumes DNS transactions.
type Consumer func(Transaction)

// Sniffer is the interface implemented by DNS transaction sniffers.
type Sniffer interface {
	// Monitor starts monitoring for DNS transactions in the background.
	Monitor(ctx context.Context, consumer Consumer) error
}

type noopSniffer struct{}

// Monitor is a no-op.
func (noopSniffer) Monitor(context.Context, Consumer) error {
	return nil
}

// NewSniffer creates a new sniffer based on the metricset's config.
func NewSniffer(base mb.BaseMetricSet, log *logp.Logger) (Sniffer, error) {
	config := defaultConfig()
	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, errors.Wrap(err, "failed to unpack dns config")
	}
	if !config.Enable {
		return noopSniffer{}, nil
	}
	factory, err := Registry.Get(config.Type)
	if err != nil {
		return nil, err
	}
	return factory(base, log)
}
