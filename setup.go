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
	//c.Next() // 'dlzmysql'
	r, err := dlzmysqlParse(c)
	if err != nil {
		return plugin.Error("dlzmysql", err)
	}

	db, _ := r.connect()
	iptable := loadIPtable()
	cache, _ := r.getCache()

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		r.Next = next
		r.DB = db
		r.Cache = cache
		r.IPtable = iptable
		return r
	})

	return nil
}

func dlzmysqlParse(c *caddy.Controller) (*Dlzmysql, error) {
	dlzmysql := Dlzmysql {}
	for c.Next() {
		if c.NextBlock() {
			for {
				switch c.Val() {
				case "address":
					if !c.NextArg() {
						return &Dlzmysql{}, c.ArgErr()
					}
					dlzmysql.mysqlAddress = c.Val()
				case "user":
					if !c.NextArg() {
						return &Dlzmysql{}, c.ArgErr()
					}
					dlzmysql.mysqlUser = c.Val()
				case "password":
					if !c.NextArg() {
						return &Dlzmysql{}, c.ArgErr()
					}
					dlzmysql.mysqlPassword = c.Val()
				case "db":
					if !c.NextArg() {
						return &Dlzmysql{}, c.ArgErr()
					}
					dlzmysql.mysqlDB = c.Val()
				default:
					if c.Val() != "}" {
						return &Dlzmysql{}, c.Errf("unknown property '%s'", c.Val())
					}
				}
				if !c.Next() {
					break
				}
			}

		}
		return &dlzmysql, nil
	}
	return &Dlzmysql{}, nil
}