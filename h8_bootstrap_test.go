package main

import (
    "os"
    "path/filepath"
    "testing"
)

func TestBootstrapPasswordRemovedAfterFirstAdminChange(t *testing.T) {
    dir := t.TempDir()
    users, err := openUsers(dir)
    if err != nil { t.Fatal(err) }
    f := filepath.Join(dir, "initial-admin-password.txt")
    if _, err = os.Stat(f); err != nil { t.Fatalf("bootstrap password was not created: %v", err) }
    if err = users.completePasswordChange("admin", "new-admin-password-123"); err != nil { t.Fatal(err) }
    if _, err = os.Stat(f); !os.IsNotExist(err) { t.Fatalf("bootstrap password still exists after first change: %v", err) }
    u, ok := users.get("admin")
    if !ok || u.MustChange { t.Fatal("admin still requires a password change") }
    if _, err = users.verify("admin", "new-admin-password-123"); err != nil { t.Fatalf("new password does not work: %v", err) }
}

func TestOrdinaryUserPasswordChangeDoesNotRemoveBootstrapFile(t *testing.T) {
    dir := t.TempDir()
    users, err := openUsers(dir)
    if err != nil { t.Fatal(err) }
    f := filepath.Join(dir, "initial-admin-password.txt")
    if err = users.add("wall", "viewer", "wallboard-pass-1"); err != nil { t.Fatal(err) }
    if err = users.completePasswordChange("wall", "wallboard-pass-2"); err != nil { t.Fatal(err) }
    if _, err = os.Stat(f); err != nil { t.Fatalf("ordinary user change removed the admin bootstrap file: %v", err) }
}

func TestLaterAdminPasswordChangeToleratesMissingBootstrapFile(t *testing.T) {
    dir := t.TempDir()
    users, err := openUsers(dir)
    if err != nil { t.Fatal(err) }
    if err = users.completePasswordChange("admin", "new-admin-password-123"); err != nil { t.Fatal(err) }
    if err = users.completePasswordChange("admin", "new-admin-password-456"); err != nil { t.Fatal(err) }
}
