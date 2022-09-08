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
import horse.wtf.nzyme.dot11.deception.traps.Trap;
import horse.wtf.nzyme.notifications.FieldNames;
import org.joda.time.DateTime;

import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class BeaconTrapResponseAlert extends Alert {

    private static final String DESCRIPTION = "A device responded to our beacon trap (" + Trap.Type.BEACON_1 + "). This " +
            "clearly indicates that an attacker is trying to lure another device to connect to their rogue access point.";

    private static final String DOC_LINK = "guidance-TRAP_BEACON_1";

    private static final List<String> FALSE_POSITIVES = new ArrayList<>() {{
        add("This can only be a false positive if you used a legitimate SSID in the trap configuration.");
    }};

    private BeaconTrapResponseAlert(DateTime timestamp, Subsystem subsystem, Map<String, Object> fields, long frameCount) {
        super(timestamp, subsystem, fields, DESCRIPTION, DOC_LINK, FALSE_POSITIVES, true, frameCount);
    }

    @Override
    public String getMessage() {
        return "Device [" + getBSSID() + "] responded to our beacon trap (" + Trap.Type.BEACON_1 + ") for [" + getSSID() + "].";
    }

    @Override
    public TYPE getType() {
        return TYPE.BEACON_TRAP_1;
    }

    public String getSSID() {
        return (String) getFields().get(FieldNames.SSID);
    }

    public String getBSSID() {
        return (String) getFields().get(FieldNames.BSSID);
    }

    @Override
    public boolean sameAs(Alert alert) {
        if (!(alert instanceof BeaconTrapResponseAlert)) {
            return false;
        }

        BeaconTrapResponseAlert a = (BeaconTrapResponseAlert) alert;

        return a.getSSID().equals(this.getSSID()) && a.getBSSID().equals(this.getBSSID());
    }

    public static BeaconTrapResponseAlert create(DateTime firstSeen, @NotNull String ssid, String bssid, int channel, int frequency, int antennaSignal, long frameCount) {
        if (Strings.isNullOrEmpty(ssid)) {
            throw new IllegalArgumentException("This alert cannot be raised for hidden/broadcast SSIDs.");
        }

        ImmutableMap.Builder<String, Object> fields = new ImmutableMap.Builder<>();
        fields.put(FieldNames.SSID, ssid);
        fields.put(FieldNames.BSSID, bssid.toLowerCase());
        fields.put(FieldNames.CHANNEL, channel);
        fields.put(FieldNames.FREQUENCY, frequency);
        fields.put(FieldNames.ANTENNA_SIGNAL, antennaSignal);

        return new BeaconTrapResponseAlert(firstSeen, Subsystem.DOT_11, fields.build(), frameCount);
    }

}
