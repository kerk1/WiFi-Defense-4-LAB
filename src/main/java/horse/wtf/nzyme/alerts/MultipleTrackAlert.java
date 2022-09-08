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

public class MultipleTrackAlert extends Alert {

    private static final String DESCRIPTION = "One of our stations is transmitting with more than one signal track. This could indicate that an attacker " +
            "is spoofing the station, causing a different signal strength than the legitimate station. If this is an attacker, the difference in signal " +
            "strength is usually caused by different physical locations of attacker and legitimate station.";
    private static final String DOC_LINK = "guidance-MULTIPLE_TRACKS";
    private static final List<String> FALSE_POSITIVES = new ArrayList<String>(){{
        add("A sudden change in the physical radio frequency environment can cause new tracks to appear. Monitor the signal track behavior long-term to spot normal changes in track behavior.");
        add("A station with adaptive transmit power can cause new tracks to be detected.");
        add("A physical relocation or configuration change of the station can cause the signal strength to change and new tracks to appear.");
    }};

    private MultipleTrackAlert(DateTime timestamp, Subsystem subsystem, Map<String, Object> fields) {
        super(timestamp, subsystem, fields, DESCRIPTION, DOC_LINK, FALSE_POSITIVES, false, -1);
    }

    @Override
    public String getMessage() {
        return "Multiple tracks detected for our SSID [" + getSSID() + "] on [" + getBSSID() + "], channel [" + getChannel() + "]. Tracks: " + getTrackCount();
    }

    @Override
    public TYPE getType() {
        return TYPE.MULTIPLE_SIGNAL_TRACKS;
    }

    public String getSSID() {
        return (String) getFields().get(FieldNames.SSID);
    }

    public String getBSSID() {
        return (String) getFields().get(FieldNames.BSSID);
    }

    public int getChannel() {
        return (int) getFields().get(FieldNames.CHANNEL);
    }

    public int getTrackCount() {
        return (int) getFields().get(FieldNames.TRACK_COUNT);
    }

    @Override
    public boolean sameAs(Alert alert) {
        if (!(alert instanceof MultipleTrackAlert)) {
            return false;
        }

        MultipleTrackAlert a = (MultipleTrackAlert) alert;

        return a.getSSID().equals(this.getSSID()) && a.getBSSID().equals(this.getBSSID()) && a.getChannel() == this.getChannel();
    }

    public static MultipleTrackAlert create(DateTime firstSeen, @NotNull String ssid, String bssid, int channel, int trackCount) {
        if (Strings.isNullOrEmpty(ssid)) {
            throw new IllegalArgumentException("This alert cannot be raised for hidden/broadcast SSIDs.");
        }

        ImmutableMap.Builder<String, Object> fields = new ImmutableMap.Builder<>();
        fields.put(FieldNames.SSID, ssid);
        fields.put(FieldNames.BSSID, bssid.toLowerCase());
        fields.put(FieldNames.CHANNEL, channel);
        fields.put(FieldNames.TRACK_COUNT, trackCount);

        return new MultipleTrackAlert(firstSeen, Subsystem.DOT_11, fields.build());
    }

}
