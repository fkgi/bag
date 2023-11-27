package bag_test

import (
	"testing"

	"github.com/fkgi/bag"
)

func TestParse(t *testing.T) {
	t.Log(bag.ParseaWWWAuthenticate(`Digest
	realm="http-auth@example.org",
	qop="auth, auth-int",
	algorithm=SHA-256,
	nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
	opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"`))
}
