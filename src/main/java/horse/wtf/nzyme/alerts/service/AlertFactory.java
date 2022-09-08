package horse.wtf.nzyme.alerts.service;

import app.nzyme.plugin.Alert;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import horse.wtf.nzyme.alerts.*;
import horse.wtf.nzyme.dot11.interceptors.misc.PwnagotchiAdvertisement;
import horse.wtf.nzyme.notifications.FieldNames;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

public class AlertFactory {

    public static Alert serializeFromDatabase(AlertDatabaseEntry db) throws IOException {
        ObjectMapper om = new ObjectMapper();
        Map<String, Object> fields = om.readValue(db.fields(), new TypeReference<Map<String, Object>>(){});

        Alert alert;
        switch (db.type()) {
            case UNEXPECTED_BSSID_BEACON:
                alert = UnexpectedBSSIDBeaconAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BSSID),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL),
                        db.frameCount()
                );
                break;
            case UNEXPECTED_BSSID_PROBERESP:
                alert = UnexpectedBSSIDProbeRespAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BSSID),
                        (String) fields.get(FieldNames.DESTINATION),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL),
                        db.frameCount()
                );
                break;
            case UNEXPECTED_SSID_BEACON:
                alert = UnexpectedSSIDBeaconAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BSSID),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL),
                        db.frameCount()
                );
                break;
            case UNEXPECTED_SSID_PROBERESP:
                alert = UnexpectedSSIDProbeRespAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BSSID),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL),
                        db.frameCount()
                );
                break;
            case CRYPTO_CHANGE_BEACON:
                alert = CryptoChangeBeaconAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BSSID),
                        (String) fields.get(FieldNames.ENCOUNTERED_SECURITY),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL),
                        db.frameCount()
                );
                break;
            case CRYPTO_CHANGE_PROBERESP:
                alert = CryptoChangeProbeRespAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BSSID),
                        (String) fields.get(FieldNames.ENCOUNTERED_SECURITY),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL),
                        db.frameCount()
                );
                break;
            case UNEXPECTED_CHANNEL_BEACON:
                alert = UnexpectedChannelBeaconAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BSSID),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL),
                        db.frameCount()
                );
                break;
            case UNEXPECTED_CHANNEL_PROBERESP:
                alert = UnexpectedChannelProbeRespAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BSSID),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL),
                        db.frameCount()
                );
                break;
            case UNEXPECTED_FINGERPRINT_BEACON:
                alert = UnexpectedFingerprintBeaconAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BANDIT_FINGERPRINT),
                        (String) fields.get(FieldNames.BSSID),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL),
                        db.frameCount()
                );
                break;
            case UNEXPECTED_FINGERPRINT_PROBERESP:
                alert = UnexpectedFingerprintProbeRespAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BANDIT_FINGERPRINT),
                        (String) fields.get(FieldNames.BSSID),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL),
                        db.frameCount()
                );
                break;
            case BEACON_RATE_ANOMALY:
                alert = BeaconRateAnomalyAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BSSID),
                        (Double) fields.get(FieldNames.BEACON_RATE),
                        (Integer) fields.get(FieldNames.BEACON_RATE_THRESHOLD)
                );
                break;
            case PROBE_RESPONSE_TRAP_1:
                alert = ProbeRequestTrapResponseAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BSSID),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL),
                        db.frameCount()
                );
                break;
            case MULTIPLE_SIGNAL_TRACKS:
                alert = MultipleTrackAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BSSID),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.TRACK_COUNT)
                );
                break;
            case PWNAGOTCHI_ADVERTISEMENT:
                alert = PwnagotchiAdvertisementAlert.create(
                        db.firstSeen(),
                        PwnagotchiAdvertisement.create(
                                (String) fields.get(FieldNames.NAME),
                                (String) fields.get(FieldNames.VERSION),
                                (String) fields.get(FieldNames.IDENTITY),
                                (Double) fields.get(FieldNames.UPTIME),
                                (Integer) fields.get(FieldNames.PWND_THIS_RUN),
                                (Integer) fields.get(FieldNames.PWND_TOTAL)
                        ),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL),
                        db.frameCount()
                );
                break;
            case BANDIT_CONTACT:
                Optional<String> ssid;
                if (fields.containsKey(FieldNames.SSID)) {
                    ssid = Optional.of((String) fields.get(FieldNames.SSID));
                } else {
                    ssid = Optional.empty();
                }

                alert = BanditContactAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.BANDIT_NAME),
                        (String) fields.get(FieldNames.BANDIT_UUID),
                        ssid,
                        db.frameCount()
                );
                break;
            case BEACON_TRAP_1:
                alert = BeaconTrapResponseAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BSSID),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL),
                        db.frameCount()
                );
                break;
            case UNKNOWN_SSID:
                alert = UnknownSSIDAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.SSID),
                        (String) fields.get(FieldNames.BSSID),
                        (Integer) fields.get(FieldNames.CHANNEL),
                        (Integer) fields.get(FieldNames.FREQUENCY),
                        (Integer) fields.get(FieldNames.ANTENNA_SIGNAL)
                );
                break;
            case PROBE_FAILURE:
                alert = ProbeFailureAlert.create(
                        db.firstSeen(),
                        (String) fields.get(FieldNames.PROBE_NAME),
                        (String) fields.get(FieldNames.ERROR_DESCRIPTION)
                );
                break;
            case DEAUTH_FLOOD:
                alert = DeauthFloodAlert.create(
                        db.firstSeen(),
                        (int) fields.get(FieldNames.DEAUTH_RATE),
                        (int) fields.get(FieldNames.GLOBAL_THRESHOLD)
                );
                break;
            default:
                throw new RuntimeException("Cannot serialize persisted alert of type [" + db.type() + "]. Not implemented.");
        }

        alert.setLastSeen(db.lastSeen());
        alert.setUUID(db.uuid());

        return alert;
    }

}
