// Package builtin wires the bundled collectors into a registry. Programs
// embedding evidencelocker can start from Registry() and register their own
// collectors alongside (see examples/customcollector).
package builtin

import (
	"github.com/archit2501/evidencelocker/pkg/collector"
	"github.com/archit2501/evidencelocker/pkg/collectors/accounts"
	"github.com/archit2501/evidencelocker/pkg/collectors/filehash"
	"github.com/archit2501/evidencelocker/pkg/collectors/persistence"
	"github.com/archit2501/evidencelocker/pkg/collectors/processes"
	"github.com/archit2501/evidencelocker/pkg/collectors/sockets"
	"github.com/archit2501/evidencelocker/pkg/collectors/users"
)

// Registry returns a fresh registry holding new instances of every
// built-in collector with default options.
func Registry() *collector.Registry {
	r := collector.NewRegistry()
	r.MustRegister(accounts.New())
	r.MustRegister(filehash.New())
	r.MustRegister(persistence.New())
	r.MustRegister(processes.New())
	r.MustRegister(sockets.New())
	r.MustRegister(users.New())
	return r
}
