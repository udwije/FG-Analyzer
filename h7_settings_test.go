package main

import (
    "encoding/json"
    "strings"
    "testing"
)

func TestH7ArrayElementDiff(t *testing.T) {
    a:=defaultConfig(t.TempDir()); b:=a
    a.InternalNetworks=[]string{"10.0.0.0/8","192.168.0.0/16"}
    b.InternalNetworks=[]string{"10.0.0.0/8","172.16.0.0/12"}
    d:=strings.Join(configDiff(a,b,[]string{"internal_networks"}), ";")
    if !strings.Contains(d,"internal_networks[1]") { t.Fatalf("element change missing: %s",d) }
}
func TestH7SecretDiffIsRedacted(t *testing.T) {
    a:=defaultConfig(t.TempDir()); b:=a
    a.Database.Password="oldsecret"; b.Database.Password="newsecret"
    d:=strings.Join(configDiff(a,b,[]string{"database"}), ";")
    if !strings.Contains(d,"secret changed") || strings.Contains(d,"oldsecret") || strings.Contains(d,"newsecret") { t.Fatalf("unsafe secret diff: %s",d) }
}
func TestH7RejectsUnknownNestedField(t *testing.T) {
    a:=defaultConfig(t.TempDir())
    _,err:=mergeSection(a,map[string]json.RawMessage{"database":json.RawMessage(`{"host":"127.0.0.1","mystery":1}`)})
    if err==nil { t.Fatal("unknown nested field accepted") }
}
