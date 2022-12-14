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

package horse.wtf.nzyme.periodicals.alerting.beaconrate;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import horse.wtf.nzyme.NzymeLeader;
import horse.wtf.nzyme.alerts.service.AlertsService;
import horse.wtf.nzyme.alerts.BeaconRateAnomalyAlert;
import horse.wtf.nzyme.configuration.leader.LeaderConfiguration;
import horse.wtf.nzyme.configuration.Dot11NetworkDefinition;
import horse.wtf.nzyme.dot11.networks.BSSID;
import horse.wtf.nzyme.dot11.networks.Networks;
import horse.wtf.nzyme.dot11.networks.SSID;
import horse.wtf.nzyme.dot11.networks.beaconrate.BeaconRate;
import horse.wtf.nzyme.periodicals.Periodical;
import horse.wtf.nzyme.util.MetricNames;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

public class BeaconRateAnomalyAlertMonitor extends Periodical {

    private static final Logger LOG = LogManager.getLogger(BeaconRateAnomalyAlertMonitor.class);

    private final Networks networks;
    private final LeaderConfiguration configuration;
    private final AlertsService alertsService;

    private final Timer timer;

    public BeaconRateAnomalyAlertMonitor(NzymeLeader nzyme) {
        this.networks = nzyme.getNetworks();
        this.configuration = nzyme.getConfiguration();
        this.alertsService = nzyme.getAlertsService();

        this.timer = nzyme.getMetrics().timer(MetricRegistry.name(MetricNames.BEACON_RATE_MONITOR_TIMING));
    }

    @Override
    protected void execute() {
        Timer.Context ctx = this.timer.time();

        try {
            for (BSSID bssid : networks.getBSSIDs().values()) {
                for (SSID ssid : bssid.ssids().values()) {
                    if (!ssid.isHumanReadable()) {
                        continue;
                    }

                    // Only run for our own networks.
                    if (!configuration.ourSSIDs().contains(ssid.name())) {
                        continue;
                    }

                    Dot11NetworkDefinition network = configuration.findNetworkDefinition(bssid.bssid(), ssid.name());
                    if (network == null) {
                        continue;
                    }

                    BeaconRate beaconRate = ssid.beaconRate();
                    if (beaconRate == null || beaconRate.rate() == null) {
                        continue;
                    }

                    if (beaconRate.rate() > network.beaconRate()) {
                        alertsService.handle(BeaconRateAnomalyAlert.create(
                                DateTime.now(),
                                ssid.name(),
                                bssid.bssid(),
                                beaconRate.rate(),
                                network.beaconRate())
                        );
                    }
                }
            }
        } catch(Exception e) {
            LOG.error("Beacon Rate Monitor run failed", e);
        } finally {
            ctx.stop();
        }

    }

    @Override
    public String getName() {
        return "BeaconRateAnomalyAlertMonitor";
    }

}
