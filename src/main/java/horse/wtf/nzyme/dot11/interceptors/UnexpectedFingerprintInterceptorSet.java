package horse.wtf.nzyme.dot11.interceptors;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import horse.wtf.nzyme.alerts.UnexpectedFingerprintBeaconAlert;
import horse.wtf.nzyme.alerts.UnexpectedFingerprintProbeRespAlert;
import horse.wtf.nzyme.alerts.service.AlertsService;
import horse.wtf.nzyme.configuration.Dot11BSSIDDefinition;
import horse.wtf.nzyme.configuration.Dot11NetworkDefinition;
import horse.wtf.nzyme.dot11.Dot11FrameInterceptor;
import horse.wtf.nzyme.dot11.Dot11FrameSubtype;
import horse.wtf.nzyme.dot11.frames.Dot11BeaconFrame;
import horse.wtf.nzyme.dot11.frames.Dot11ProbeResponseFrame;
import org.joda.time.DateTime;

import java.util.ArrayList;
import java.util.List;

public class UnexpectedFingerprintInterceptorSet {

    private final List<Dot11NetworkDefinition> configuredNetworks;

    private final AlertsService alerts;

    public UnexpectedFingerprintInterceptorSet(AlertsService alerts, List<Dot11NetworkDefinition> configuredNetworks) {
        this.alerts = alerts;
        this.configuredNetworks = configuredNetworks;
    }

    public List<Dot11FrameInterceptor> getInterceptors() {
        ImmutableList.Builder<Dot11FrameInterceptor> interceptors = new ImmutableList.Builder<>();

        // React on probe-resp frames from one of our BSSIDs that is advertising a network that is not ours.
        interceptors.add(new Dot11FrameInterceptor<Dot11ProbeResponseFrame>() {
            @Override
            public void intercept(Dot11ProbeResponseFrame frame) {
                // Don't consider broadcast frames.
                if (frame.ssid() == null) {
                    return;
                }

                for (Dot11NetworkDefinition network : configuredNetworks) {
                    for (Dot11BSSIDDefinition bssid : network.bssids()) {
                        if (!Strings.isNullOrEmpty(frame.transmitterFingerprint())
                                && frame.transmitter().equals(bssid.address())
                                && !bssid.fingerprints().contains(frame.transmitterFingerprint())) {
                            alerts.handle(UnexpectedFingerprintProbeRespAlert.create(
                                    DateTime.now(),
                                    frame.ssid(),
                                    frame.transmitterFingerprint(),
                                    frame.transmitter(),
                                    frame.meta().getChannel(),
                                    frame.meta().getFrequency(),
                                    frame.meta().getAntennaSignal(),
                                    1
                            ));
                        }
                    }
                }
            }

            @Override
            public byte forSubtype() {
                return Dot11FrameSubtype.PROBE_RESPONSE;
            }

            @Override
            public List<Class<? extends Alert>> raisesAlerts() {
                return new ArrayList<Class<? extends Alert>>(){{
                    add(UnexpectedFingerprintProbeRespAlert.class);
                }};
            }
        });

        // React on beacon frames from one of our BSSIDs that is advertising a network that is not ours.
        interceptors.add(new Dot11FrameInterceptor<Dot11BeaconFrame>() {
            @Override
            public void intercept(Dot11BeaconFrame frame) {
                // Don't consider broadcast frames.
                if (frame.ssid() == null) {
                    return;
                }

                for (Dot11NetworkDefinition network : configuredNetworks) {
                    for (Dot11BSSIDDefinition bssid : network.bssids()) {
                        if (!Strings.isNullOrEmpty(frame.transmitterFingerprint())
                                && frame.transmitter().equals(bssid.address())
                                && !bssid.fingerprints().contains(frame.transmitterFingerprint())) {
                            alerts.handle(UnexpectedFingerprintBeaconAlert.create(
                                    DateTime.now(),
                                    frame.ssid(),
                                    frame.transmitterFingerprint(),
                                    frame.transmitter(),
                                    frame.meta().getChannel(),
                                    frame.meta().getFrequency(),
                                    frame.meta().getAntennaSignal(),
                                    1
                            ));
                        }
                    }
                }
            }

            @Override
            public byte forSubtype() {
                return Dot11FrameSubtype.BEACON;
            }

            @Override
            public List<Class<? extends Alert>> raisesAlerts() {
                return new ArrayList<Class<? extends Alert>>(){{
                    add(UnexpectedFingerprintBeaconAlert.class);
                }};
            }
        });

        return interceptors.build();
    }


}
