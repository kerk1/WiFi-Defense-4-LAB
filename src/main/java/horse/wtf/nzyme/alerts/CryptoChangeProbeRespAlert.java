/*
 * This file is part of nzyme.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

package horse.wtf.nzyme.alerts;

import app.nzyme.plugin.Alert;
import app.nzyme.plugin.Subsystem;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import horse.wtf.nzyme.notifications.FieldNames;
import org.joda.time.DateTime;

import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CryptoChangeProbeRespAlert extends Alert {

    private static final String DESCRIPTION = "A station is replying to devices that are looking for one of our networks (probing) and is using an unexpected wireless " +
            "security mechanism. This could indicate that an attacker is spoofing your SSID (network name) but does not know the correct " +
            "password. Without the correct password, clients will not connect. The attacker might be trying to simply leave out the password (note that most modern " +
            "devices will refuse to connect to a network that used to have a password but suddenly does not have one) or try a downgrade attack to exploit less secure " +
            "mechanisms. It could also indicate spoofing without attempting to properly replicate the original security mechanisms.";
    private static final String DOC_LINK = "guidance-CRYPTO_CHANGE";
    private static final List<String> FALSE_POSITIVES = new ArrayList<String>(){{
        add("A legitimate configuration change of an access point could have caused this.");
    }};

    private CryptoChangeProbeRespAlert(DateTime timestamp, Subsystem subsystem, Map<String, Object> fields, long frameCount) {
        super(timestamp, subsystem, fields, DESCRIPTION, DOC_LINK, FALSE_POSITIVES, true, frameCount);
    }

    @Override
    public String getMessage() {
        return "SSID [" + getSSID() + "] was advertised with unexpected security settings [" + getEncounteredSecurity() + "].";
    }

    @Override
    public TYPE getType() {
        return TYPE.CRYPTO_CHANGE_PROBERESP;
    }

    public String getSSID() {
        return (String) getFields().get(FieldNames.SSID);
    }

    public String getBSSID() {
        return (String) getFields().get(FieldNames.BSSID);
    }

    public String getEncounteredSecurity() {
        return (String) getFields().get(FieldNames.ENCOUNTERED_SECURITY);
    }

    @Override
    public boolean sameAs(Alert alert) {
        if (!(alert instanceof CryptoChangeProbeRespAlert)) {
            return false;
        }

        CryptoChangeProbeRespAlert a = (CryptoChangeProbeRespAlert) alert;

        return a.getSSID().equals(this.getSSID())
                && a.getBSSID().equals(this.getBSSID())
                && a.getEncounteredSecurity().equals(this.getEncounteredSecurity());
    }

    public static CryptoChangeProbeRespAlert create(DateTime firstSeen, @NotNull String ssid, String bssid, String encounteredSecurity, int channel, int frequency, int antennaSignal, long frameCount) {
        if (Strings.isNullOrEmpty(ssid)) {
            throw new IllegalArgumentException("This alert cannot be raised for hidden/broadcast SSIDs.");
        }

        ImmutableMap.Builder<String, Object> fields = new ImmutableMap.Builder<>();
        fields.put(FieldNames.SSID, ssid);
        fields.put(FieldNames.BSSID, bssid.toLowerCase());
        fields.put(FieldNames.ENCOUNTERED_SECURITY, encounteredSecurity);
        fields.put(FieldNames.CHANNEL, channel);
        fields.put(FieldNames.FREQUENCY, frequency);
        fields.put(FieldNames.ANTENNA_SIGNAL, antennaSignal);

        return new CryptoChangeProbeRespAlert(firstSeen, Subsystem.DOT_11, fields.build(), frameCount);
    }


}
