package shangmiinterop

import "testing"

func TestShangMiKeyUpdate(t *testing.T) {
	if *native == "" {
		t.Fatal("missing native peer")
	}
	f := credentials(t, nil)
	client := clientCredentials(t, nil)
	for _, scenario := range []string{"key_update_one_way", "key_update_requested", "key_update_coalesced"} {
		t.Run("native_server_"+scenario, func(t *testing.T) { runNativeServer(t, f, "close", scenario) })
		t.Run("native_client_"+scenario, func(t *testing.T) { runNativeClient(t, f, "localhost", true, scenario) })
		t.Run("native_mtls_server_"+scenario, func(t *testing.T) { runNativeServerWithClient(t, f, &client, "close", scenario) })
	}
	for _, scenario := range []string{"key_update_bad_value", "key_update_bad_length", "key_update_bad_stale_key"} {
		t.Run(scenario, func(t *testing.T) { runNativeServer(t, f, "keyupdate-fail", scenario) })
		t.Run("mtls_"+scenario, func(t *testing.T) { runNativeServerWithClient(t, f, &client, "keyupdate-fail", scenario) })
	}
}
