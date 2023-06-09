package helper

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/x-pack/auditbeat/tracing"
)

// ProbeDef couples a probe with a decoder factory.
type ProbeDef struct {
	Probe   tracing.Probe
	Decoder func(desc tracing.ProbeFormat) (tracing.Decoder, error)
}

// ApplyTemplate returns a new probe definition after expanding all templates.
func (pdef ProbeDef) ApplyTemplate(vars common.MapStr) ProbeDef {
	pdef.Probe.Address = applyTemplate(pdef.Probe.Address, vars)
	pdef.Probe.Fetchargs = applyTemplate(pdef.Probe.Fetchargs, vars)
	pdef.Probe.Filter = applyTemplate(pdef.Probe.Filter, vars)
	return pdef
}

func applyTemplate(s string, vars common.MapStr) string {
	buf := &bytes.Buffer{}
	if err := template.Must(template.New("").Parse(s)).Execute(buf, vars); err != nil {
		panic(err)
	}
	return buf.String()
}

// NewStructDecoder is a helper to create struct decoder fatories
// for a give allocator function.
func NewStructDecoder(allocator tracing.AllocateFn) func(tracing.ProbeFormat) (tracing.Decoder, error) {
	return func(format tracing.ProbeFormat) (tracing.Decoder, error) {
		return tracing.NewStructDecoder(format, allocator)
	}
}

// MakeMemoryDump returns a kprobe fetchargs definition that reads a region
// of memory using a sequece of 8-byte fields.
func MakeMemoryDump(address string, from, to int) string {
	var params []string
	for off := from; off < to; off += 8 {
		params = append(params, fmt.Sprintf("+%d(%s):u64", off, address))
	}
	return strings.Join(params, " ")
}
