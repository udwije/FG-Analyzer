package snmp
import "testing"
func TestAuthenticationParameterLengths(t *testing.T) { for _, x := range []struct{p AuthProto; n int}{{AuthMD5,12},{AuthSHA1,12},{AuthSHA256,24},{AuthSHA512,48}} { if x.p.tagLen()!=x.n { t.Fatalf("%s tagLen=%d want %d",x.p,x.p.tagLen(),x.n) } } }
