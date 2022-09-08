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

package horse.wtf.nzyme.rest.resources;

import com.google.common.collect.Lists;
import horse.wtf.nzyme.NzymeLeader;
import horse.wtf.nzyme.bandits.Contact;
import horse.wtf.nzyme.bandits.engine.ContactRecordAggregation;
import horse.wtf.nzyme.bandits.engine.ContactRecorder;
import horse.wtf.nzyme.dot11.deauth.db.DeauthenticationMonitorRecording;
import horse.wtf.nzyme.dot11.probes.Dot11Probe;
import horse.wtf.nzyme.measurements.Measurement;
import horse.wtf.nzyme.measurements.MeasurementType;
import horse.wtf.nzyme.rest.authentication.RESTSecured;
import horse.wtf.nzyme.rest.responses.alerts.AlertDetailsResponse;
import horse.wtf.nzyme.rest.responses.alerts.AlertsListResponse;
import horse.wtf.nzyme.rest.responses.bandits.ContactResponse;
import horse.wtf.nzyme.rest.responses.dashboard.DashboardResponse;
import horse.wtf.nzyme.rest.responses.system.ProbeResponse;
import horse.wtf.nzyme.rest.responses.system.ProbesListResponse;
import horse.wtf.nzyme.systemstatus.SystemStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;

@Path("/api/dashboard")
@RESTSecured
@Produces(MediaType.APPLICATION_JSON)
public class DashboardResource {

    private static final Logger LOG = LogManager.getLogger(DashboardResource.class);

    private static final String MEASUREMENTS_QUERY = "SELECT * FROM measurements WHERE measurement_type = ? AND created_at > (current_timestamp at time zone 'UTC' - interval '1 day') ORDER BY created_at ASC;";
    private static final String DEAUTH_QUERY = "SELECT * FROM deauth_monitor WHERE created_at > (current_timestamp - interval '1 day') ORDER BY created_at ASC;";

    @Inject
    private NzymeLeader nzyme;

    @GET
    public Response dashboard() {
        long activeAlerts = nzyme.getAlertsService().findActiveAlerts().size();
        long activeContacts = 0;

        List<AlertDetailsResponse> alerts = Lists.newArrayList();
        for (Alert alert : nzyme.getAlertsService().findAllAlerts(5, 0).values()) {
            alerts.add(AlertDetailsResponse.fromAlert(alert));
        }

        for (Contact contact : nzyme.getContactManager().findContacts().values()) {
            if (contact.isActive()) {
                activeContacts++;
            }
        }

        SystemStatus.HEALTH systemHealthStatus = nzyme.getSystemStatus().decideHealth(nzyme);

        Map<String, Long> frameThroughputHistogram = buildMeasurementHistogram(nzyme.getDatabase().withHandle(handle ->
                handle.createQuery(MEASUREMENTS_QUERY)
                        .bind(0, MeasurementType.DOT11_FRAME_COUNT)
                        .mapTo(Measurement.class)
                        .list()
        ));

        Map<String, Long> deauthHistogram = buildDeauthHistogram(nzyme.getDatabase().withHandle(handle ->
                handle.createQuery(DEAUTH_QUERY)
                        .mapTo(DeauthenticationMonitorRecording.class)
                        .list()
        ));

        List<ContactResponse> contacts = Lists.newArrayList();

        for (Contact contact : nzyme.getContactManager().findContacts(5, 0).values()) {
            if (contact.bandit() == null || contact.bandit().uuid() == null) {
                LOG.warn("Skipping unexpected incomplete contact [{}].", contact);
                continue;
            }
            Optional<List<ContactRecordAggregation>> ssids = nzyme.getContactManager().findRecordValuesOfContact(contact.uuid(), ContactRecorder.RECORD_TYPE.SSID);
            Optional<List<ContactRecordAggregation>> bssids = nzyme.getContactManager().findRecordValuesOfContact(contact.uuid(), ContactRecorder.RECORD_TYPE.BSSID);

            contacts.add(ContactResponse.create(
                    contact.uuid(),
                    contact.frameCount(),
                    contact.firstSeen(),
                    contact.lastSeen(),
                    contact.isActive(),
                    contact.lastSignal(),
                    contact.bandit().uuid().toString(),
                    contact.bandit().name(),
                    contact.sourceRole().toString(),
                    contact.sourceName(),
                    ssids.orElse(Collections.emptyList()),
                    bssids.orElse(Collections.emptyList())
            ));
        }

        List<ProbeResponse> probes = Lists.newArrayList();
        for (Dot11Probe probe : nzyme.getProbes()) {
            probes.add(ProbeResponse.create(
                    probe.getName(),
                    probe.getClass().getSimpleName(),
                    probe.getConfiguration().networkInterfaceName(),
                    probe.isInLoop(),
                    probe.isActive(),
                    probe.getConfiguration().channels(),
                    probe.getCurrentChannel(),
                    probe.getTotalFrames()
            ));
        }

        return Response.ok(
                DashboardResponse.create(
                        activeAlerts,
                        activeContacts,
                        systemHealthStatus,
                        frameThroughputHistogram,
                        deauthHistogram,
                        nzyme.getConfiguration().deauth() == null ? null : nzyme.getConfiguration().deauth().globalThreshold(),
                        AlertsListResponse.create(alerts.size(), alerts),
                        contacts,
                        ProbesListResponse.create(probes.size(), probes)
                )
        ).build();
    }

    private Map<String, Long> buildMeasurementHistogram(List<Measurement> measurements) {
        Map<String, Long> clientCountHistogram = buildEmptyDailyHistogram();

        if (measurements != null && !measurements.isEmpty()) {
            for (Measurement measurement : measurements) {
                clientCountHistogram.put(measurement.createdAt().withZone(DateTimeZone.UTC).withSecondOfMinute(0).withMillisOfSecond(0).toString(), measurement.value());
            }
        }

        return clientCountHistogram;
    }

    private Map<String, Long> buildDeauthHistogram(List<DeauthenticationMonitorRecording> recordings) {
        Map<String, Long> deauthHistogram = buildEmptyDailyHistogram();

        if (recordings != null && !recordings.isEmpty()) {
            for (DeauthenticationMonitorRecording recording : recordings) {
                deauthHistogram.put(recording.createdAt().withZone(DateTimeZone.UTC).withSecondOfMinute(0).withMillisOfSecond(0).toString(), recording.totalFrameCount());
            }
        }

        return deauthHistogram;
    }

    private Map<String, Long> buildEmptyDailyHistogram() {
        Map<String, Long> histo = new TreeMap<>();

        // Always have an x-axis for full 24 hours to avoid weird diagonal connections.
        for (int i = 1; i < 24*60; i++) {
            histo.put(DateTime.now(DateTimeZone.UTC).minusMinutes(i).withSecondOfMinute(0).withMillisOfSecond(0).toString(), 0L);
        }

        return histo;
    }

}
