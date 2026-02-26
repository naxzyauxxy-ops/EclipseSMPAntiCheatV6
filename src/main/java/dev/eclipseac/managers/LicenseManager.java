package dev.eclipseac.managers;

import dev.eclipseac.EclipseAC;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public class LicenseManager {

    // Change this before distributing — must match the secret in your keygen
    private static final String SECRET = "EclipseAC-Private-Secret-2025-ChangeMe";

    private final EclipseAC plugin;
    private boolean valid = false;

    public LicenseManager(EclipseAC plugin) {
        this.plugin = plugin;
    }

    public boolean validate() {
        String key = plugin.getConfig().getString("license.key", "");

        if (key.isEmpty() || key.equalsIgnoreCase("YOUR-LICENSE-KEY-HERE")) {
            plugin.getLogger().severe("[EclipseAC] No license key set in config.yml.");
            return false;
        }

        if (isValidKey(key)) {
            plugin.getLogger().info("[EclipseAC] License validated.");
            valid = true;
            return true;
        }

        plugin.getLogger().severe("[EclipseAC] Invalid license key.");
        return false;
    }

    private boolean isValidKey(String key) {
        String[] parts = key.split("-");
        if (parts.length != 5) return false;
        if (!parts[0].equals("ECLIPSE")) return false;

        String id        = parts[1] + "-" + parts[2] + "-" + parts[3];
        String signature = parts[4];
        String expected  = hmac(id, SECRET);

        return expected.equalsIgnoreCase(signature);
    }

    public static String generateKey(String id) {
        String sig = hmac(id, SECRET);
        return "ECLIPSE-" + id + "-" + sig;
    }

    private static String hmac(String data, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] raw = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                sb.append(String.format("%02X", raw[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("HMAC failed", e);
        }
    }

    public boolean isValid() { return valid; }
}
