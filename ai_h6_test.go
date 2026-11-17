package main
import "testing"
func TestH6DomainGrouping(t *testing.T) {
 cases := map[string]string{"api.x.ai":"x.ai","chat.x.ai":"x.ai","foo.bar.io":"bar.io","a.example.com.lk":"example.com.lk","192.0.2.1":"192.0.2.1"}
 for in,want := range cases { if got:=rootDomain(in); got!=want { t.Errorf("rootDomain(%q)=%q want %q",in,got,want) } }
}
func TestH6DomainPatternBoundary(t *testing.T) {
 re:=patternRegexp("x.ai")
 for _,s:=range []string{"x.ai","api.x.ai","chat.x.ai"} { if !re.MatchString(s) { t.Errorf("expected match %q",s) } }
 for _,s:=range []string{"notx.ai","x.ai.evil.example"} { if re.MatchString(s) { t.Errorf("unexpected match %q",s) } }
}
