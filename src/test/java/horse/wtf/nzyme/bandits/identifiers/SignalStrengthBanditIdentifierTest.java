package horse.wtf.nzyme.bandits.identifiers;

import com.codahale.metrics.MetricRegistry;
import horse.wtf.nzyme.dot11.MalformedFrameException;
import horse.wtf.nzyme.dot11.anonymization.Anonymizer;
import horse.wtf.nzyme.dot11.parsers.Dot11BeaconFrameParser;
import horse.wtf.nzyme.dot11.parsers.Dot11DeauthenticationFrameParser;
import horse.wtf.nzyme.dot11.parsers.Dot11ProbeResponseFrameParser;
import horse.wtf.nzyme.dot11.parsers.Frames;
import org.pcap4j.packet.IllegalRawDataException;
import org.testng.annotations.Test;

import java.util.Optional;

import static org.testng.Assert.*;

public class SignalStrengthBanditIdentifierTest {

    @Test(expectedExceptions = {IllegalArgumentException.class})
    public void testDoesNotAllowOutOfRangeFromValue() {
        new SignalStrengthBanditIdentifier(10, -50, null, null);
    }

    @Test(expectedExceptions = {IllegalArgumentException.class})
    public void testDoesNotAllowOutOfRangeToValue() {
        new SignalStrengthBanditIdentifier(-15, -110, null, null);
    }

    @Test(expectedExceptions = {IllegalArgumentException.class})
    public void testDoesNotAllowFromValueLowerThanToValue() {
        new SignalStrengthBanditIdentifier(-50, -15, null, null);
    }

    @Test
    public void testDescriptor() {
        BanditIdentifier id = new SignalStrengthBanditIdentifier(-15, -50, null, null);

        assertEquals(id.descriptor(), BanditIdentifierDescriptor.create(
                BanditIdentifier.TYPE.SIGNAL_STRENGTH,
                "Matches if the frame signal strength is within expected range.",
                "(frame.signal_quality >= -50 AND frame.signal_quality <= -15)"
        ));
    }

    @Test
    public void testMatchesBeacon() throws MalformedFrameException, IllegalRawDataException {
        BanditIdentifier id = new SignalStrengthBanditIdentifier(-15, -50, null, null);

        Optional<Boolean> result = id.matches(new Dot11BeaconFrameParser(new MetricRegistry(), new Anonymizer(false, "")).parse(Frames.BEACON_1_PAYLOAD, Frames.BEACON_1_HEADER, signal(-35)));

        assertTrue(result.isPresent());
        assertTrue(result.get());
    }

    @Test
    public void testMatchesProbeResp() throws MalformedFrameException, IllegalRawDataException {
        BanditIdentifier id = new SignalStrengthBanditIdentifier(-15, -50, null, null);

        Optional<Boolean> result = id.matches(new Dot11ProbeResponseFrameParser(new MetricRegistry(), new Anonymizer(false, "")).parse(Frames.PROBE_RESP_1_PAYLOAD, Frames.PROBE_RESP_1_HEADER, signal(-35)));

        assertTrue(result.isPresent());
        assertTrue(result.get());
    }

    @Test
    public void testMatchesDeauth() throws MalformedFrameException, IllegalRawDataException {
        BanditIdentifier id = new SignalStrengthBanditIdentifier(-15, -50, null, null);

        Optional<Boolean> result = id.matches(new Dot11DeauthenticationFrameParser(new MetricRegistry(), new Anonymizer(false, "")).parse(Frames.DEAUTH_1_PAYLOAD, Frames.DEAUTH_1_HEADER, signal(-35)));

        assertTrue(result.isPresent());
        assertTrue(result.get());
    }

    @Test
    public void testIgnoresBeacon() throws MalformedFrameException, IllegalRawDataException {
        BanditIdentifier id = new SignalStrengthBanditIdentifier(-15, -50, null, null);

        Optional<Boolean> result = id.matches(new Dot11BeaconFrameParser(new MetricRegistry(), new Anonymizer(false, "")).parse(Frames.BEACON_1_PAYLOAD, Frames.BEACON_1_HEADER, signal(-55)));

        assertTrue(result.isPresent());
        assertFalse(result.get());
    }

    @Test
    public void testIgnoresProbeResp() throws MalformedFrameException, IllegalRawDataException {
        BanditIdentifier id = new SignalStrengthBanditIdentifier(-15, -50, null, null);

        Optional<Boolean> result = id.matches(new Dot11ProbeResponseFrameParser(new MetricRegistry(), new Anonymizer(false, "")).parse(Frames.PROBE_RESP_1_PAYLOAD, Frames.PROBE_RESP_1_HEADER, signal(-55)));

        assertTrue(result.isPresent());
        assertFalse(result.get());
    }

    @Test
    public void testIgnoresDeauth() throws MalformedFrameException, IllegalRawDataException {
        BanditIdentifier id = new SignalStrengthBanditIdentifier(-15, -50, null, null);

        Optional<Boolean> result = id.matches(new Dot11DeauthenticationFrameParser(new MetricRegistry(), new Anonymizer(false, "")).parse(Frames.DEAUTH_1_PAYLOAD, Frames.DEAUTH_1_HEADER, signal(-55)));

        assertTrue(result.isPresent());
        assertFalse(result.get());
    }

    private Dot11MetaInformation signal(int antennaSignal) {
        return new Dot11MetaInformation(false, antennaSignal, 9001, 11, 0L, false);
    }

}