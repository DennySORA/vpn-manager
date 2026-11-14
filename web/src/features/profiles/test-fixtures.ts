// Test data for the WireGuard profile tests (not used by the app).
import type { RuntimeProfile } from "@/api/types";

/** An imported generic profile (the fixture connection `view()` uses `p1`). */
export function profile(p: Partial<RuntimeProfile> = {}): RuntimeProfile {
  return {
    id: "p1",
    name: "Lab peer（東京）",
    provider: "generic",
    source: { kind: "imported" },
    interface: {
      private_key: "s1",
      public_key: "BDD1YvkYaZVAxy0uV8Geto3Gz/470ss65WWexl63RVE=",
      addresses: ["10.99.0.2/32", "fd99::2/128"],
      dns: ["10.99.0.1"],
      mtu: 1420,
    },
    peer: {
      public_key: "GVTegLrzQNs7jTszbPH9rkXIV0ziopxzgmarYqbTJzs=",
      preshared_key: null,
      endpoint: "203.0.113.10:51820",
      allowed_ips: ["0.0.0.0/0", "::/0"],
      persistent_keepalive: 25,
    },
    location: { country_code: "JP", country: "日本", city: "東京", server: "lab-tyo-01" },
    expires_at: null,
    revision: 1,
    created_at: "2026-11-01T00:00:00Z",
    updated_at: "2026-11-01T00:00:00Z",
    ...p,
  };
}

/** A profile built by AirVPN account `a1`. */
export function airvpnProfile(p: Partial<RuntimeProfile> = {}): RuntimeProfile {
  return profile({
    id: "p2",
    name: "AirVPN · 荷蘭 piautos",
    provider: "airvpn",
    source: { kind: "provider", account_id: "a1", device_id: "Default", server_id: "piautos" },
    location: { country_code: "NL", country: "荷蘭", city: "阿姆斯特丹", server: "piautos" },
    ...p,
  });
}
