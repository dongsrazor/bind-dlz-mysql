// +build fuzz

package dlzmysql

import (
	"github.com/coredns/coredns/plugin/pkg/fuzz"
)

// Fuzz fuzzes cache.
func Fuzz(data []byte) int {
	w := Dlzmysql{}
	return fuzz.Do(w, data)
}
