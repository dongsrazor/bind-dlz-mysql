package dlzmysql

import (
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/mholt/caddy"
)

func init() {
	caddy.RegisterPlugin("dlzmysql", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	c.Next() // 'dlzmysql'
	if c.NextArg() {
		return plugin.Error("dlzmysql", c.ArgErr())
	}
	iptable := loadIPtable()
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Dlzmysql{Next: next, IPtable: iptable}
	})

	return nil
}
