package helper

import "github.com/elastic/beats/v7/x-pack/auditbeat/tracing"

// Logger exposes logging functions.
type Logger interface {
	Errorf(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Debugf(format string, args ...interface{})
}

// ProbeCondition is a function that allow to filter probes.
type ProbeCondition func(probe tracing.Probe) bool

// ProbeInstaller interface allows to install and uninstall kprobes.
type ProbeInstaller interface {
	// Install installs the given kprobe, returning its format and decoder.
	Install(pdef ProbeDef) (format tracing.ProbeFormat, decoder tracing.Decoder, err error)

	// UninstallInstalled removes all kprobes that have been installed by the 
	// Install method.
	UninstallInstalled() error

	// UninstallIf uninstalls all kprobes that match a condition.
	// Works on all existing kprobes, not only those installed b y Install, so
	// it allows to cleanup dangling probes from a previous run.
	UninstallIf(condition ProbeCondition) error
}