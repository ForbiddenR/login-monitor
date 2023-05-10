package afpackets

import (
	"context"
	"net"

	parent "github.com/ForbiddenR/login-monitor/auditbeat/socket/dns"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

var udpSrcPort53Filter = []bpf.RawInstruction{
	{Op: 0x28, Jt: 0x0, Jf: 0x0, K: 0xc},
	{Op: 0x15, Jt: 0x0, Jf: 0x4, K: 0x86dd},
	{Op: 0x30, Jt: 0x0, Jf: 0x0, K: 0x14},
	{Op: 0x15, Jt: 0x0, Jf: 0xb, K: 0x11},
	{Op: 0x28, Jt: 0x0, Jf: 0x0, K: 0x36},
	{Op: 0x15, Jt: 0x8, Jf: 0x9, K: 0x35},
	{Op: 0x15, Jt: 0x0, Jf: 0x8, K: 0x800},
	{Op: 0x30, Jt: 0x0, Jf: 0x0, K: 0x17},
	{Op: 0x15, Jt: 0x0, Jf: 0x6, K: 0x11},
	{Op: 0x28, Jt: 0x0, Jf: 0x0, K: 0x14},
	{Op: 0x45, Jt: 0x4, Jf: 0x0, K: 0x1fff},
	{Op: 0xb1, Jt: 0x0, Jf: 0x0, K: 0xe},
	{Op: 0x48, Jt: 0x0, Jf: 0x0, K: 0xe},
	{Op: 0x15, Jt: 0x0, Jf: 0x1, K: 0x35},
	{Op: 0x6, Jt: 0x0, Jf: 0x0, K: 0xffff},
	{Op: 0x6, Jt: 0x0, Jf: 0x0, K: 0x0},
}

type dnsCapture struct {
	tPacket *afpacket.TPacket
	log     *logp.Logger
}

func init() {
	// parent.Registry.MustRegister("af_packet", )
}

// func newAFPacketSniffer(base mb.BaseMetricSet, log *logp.Logger) (parent.Sniffer, error) {
// 	config := defaultConfig()
// 	if err := base.Module().UnpackConfig(&config); err != nil {
// 		return nil, errors.Wrap(err, "failed to unpack af_packet config")
// 	}

// }

var (
	errNotIP  = errors.New("network is not IP")
	errNotUDP = errors.New("transport is not UDP")
)

func dupSlice(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func getEndpoints(pkt gopacket.Packet) (src net.UDPAddr, dst net.UDPAddr, err error) {
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return src, dst, errNotIP
	}
	switch v := netLayer.(type) {
	case *layers.IPv4:
		src.IP = dupSlice(v.SrcIP)
		dst.IP = dupSlice(v.DstIP)
	case *layers.IPv6:
		src.IP = dupSlice(v.SrcIP)
		dst.IP = dupSlice(v.DstIP)
	default:
		return src, dst, errNotIP
	}
	transLayer := pkt.TransportLayer()
	if transLayer == nil ||
		transLayer.LayerType() != layers.LayerTypeUDP {
		return src, dst, errNotUDP
	}
	udp, ok := transLayer.(*layers.UDP)
	if !ok {
		return src, dst, errNotUDP
	}
	src.Port = int(udp.SrcPort)
	dst.Port = int(udp.DstPort)
	return src, dst, nil
}

func (c *dnsCapture) run(ctx context.Context, consumer parent.Consumer) {
	defer c.tPacket.Close()
	source := gopacket.ZeroCopyPacketDataSource(c.tPacket)
	c.log.Info("Starting DNS capture.")
	defer c.log.Info("Stopping DNS capture.")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		data, _, err := source.ZeroCopyReadPacketData()
		if err != nil {
			if err == afpacket.ErrTimeout {
				continue
			}
			c.log.Error("DNS capture error", err)
			return
		}

		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		src, dst, err := getEndpoints(pkt)
		if err != nil {
			c.log.Warn("Failed to decode UDP packet.", err)
			continue
		}
		msg := &dns.Msg{}
		if err = msg.Unpack(pkt.TransportLayer().LayerPayload()); err != nil {
			c.log.Warn("Failed to unpack UDP payload from port 53.", err)
			continue
		}

		if len(msg.Question) == 0 || (msg.Question[0].Qtype != dns.TypeA && msg.Question[0].Qtype != dns.TypeAAAA) {
			continue
		}
		questionName := trimRightDot(msg.Question[0].Name)
		tr := parent.Transaction{
			TXID:      msg.Id,
			Client:    dst,
			Server:    src,
			Domain:    questionName,
			Addresses: make([]net.IP, 0, len(msg.Answer)),
		}
		for _, ans := range msg.Answer {
			switch ans.Header().Rrtype {
			case dns.TypeA:
				if a, ok := ans.(*dns.A); ok {
					tr.Addresses = append(tr.Addresses, a.A)
				} else {
					c.log.Debug("Unexpected type for DNS A response")
				}
			case dns.TypeAAAA:
				if a, ok := ans.(*dns.AAAA); ok {
					tr.Addresses = append(tr.Addresses, a.AAAA)
				} else {
					c.log.Debug("Unexpected type for DNS AAAA response")
				}
			default:
				continue
			}
		}
		if len(tr.Addresses) > 0 {
			if c.log.IsDebug() {
				c.log.Debugf("Got DNS transaction client=%s server=%s domain=%s addresses=%v",
					tr.Client.String(),
					tr.Server.String(),
					tr.Domain,
					tr.Addresses)
			}
			consumer(tr)
		}
	}
}

// afpacketComputeSize computes the block_size and the num_blocks in such a way
// that the allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that block_size must be divisible by both the
// frame size and page size.
func afpacketComputeSize(targetSize int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {

	if snaplen < pageSize {
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}

	// 128 is the default from the gopacket library so jsut use that
	blockSize = frameSize * 128
	numBlocks = targetSize / blockSize

	if numBlocks == 0 {
		return 0, 0, 0, errors.New("Interface buffersize is too small")
	}

	return frameSize, blockSize, numBlocks, nil
}

func trimRightDot(name string) string {
	if len(name) == 0 || name == "." || name[len(name)-1] != '.' {
		return name
	}
	return name[:len(name)-1]
}
