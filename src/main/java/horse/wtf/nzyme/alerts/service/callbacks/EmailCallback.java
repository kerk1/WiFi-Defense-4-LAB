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

package horse.wtf.nzyme.alerts.service.callbacks;

import com.google.auto.value.AutoValue;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.typesafe.config.Config;
import freemarker.template.Template;
import freemarker.template.TemplateExceptionHandler;
import horse.wtf.nzyme.configuration.ConfigurationKeys;
import horse.wtf.nzyme.configuration.ConfigurationValidator;
import horse.wtf.nzyme.configuration.IncompleteConfigurationException;
import horse.wtf.nzyme.configuration.InvalidConfigurationException;
import horse.wtf.nzyme.util.Tools;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.simplejavamail.api.email.Email;
import org.simplejavamail.api.email.Recipient;
import org.simplejavamail.api.mailer.Mailer;
import org.simplejavamail.api.mailer.config.TransportStrategy;
import org.simplejavamail.email.EmailBuilder;
import org.simplejavamail.mailer.MailerBuilder;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

public class EmailCallback implements AlertCallback {

    private static final Logger LOG = LogManager.getLogger(EmailCallback.class);

    private final Configuration configuration;
    private final Mailer mailer;

    private final freemarker.template.Configuration templateConfig;

    public EmailCallback(Configuration configuration) {
        this.configuration = configuration;
        this.mailer = MailerBuilder
                .withSMTPServer(configuration.host(), configuration.port(), configuration.username(), configuration.password())
                .withTransportStrategy(configuration.transportStrategy())
                .clearEmailAddressCriteria()
                .buildMailer();

        // Set up template engine.
        this.templateConfig = new freemarker.template.Configuration(freemarker.template.Configuration.VERSION_2_3_30);
        this.templateConfig.setClassForTemplateLoading(this.getClass(), "/");
        this.templateConfig.setDefaultEncoding("UTF-8");
        this.templateConfig.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        this.templateConfig.setLogTemplateExceptions(false);
        this.templateConfig.setWrapUncheckedExceptions(true);
        this.templateConfig.setFallbackOnNullLoopVariable(false);
    }

    @Override
    public void call(Alert alert) {
        LOG.info("Sending alert email.");
        try {
            Email email = EmailBuilder.startingBlank()
                    .to(configuration.recipients())
                    .from(configuration.from())
                    .withSubject(configuration.subjectPrefix() + " " + buildSubject(alert))
                    .withPlainText(buildPlainTextBody(alert))
                    .withHTMLText(buildHTMLTextBody(alert))
                    .withEmbeddedImage("nzyme_logo", loadLogoFile(), "image/png")
                    .buildEmail();

            mailer.sendMail(email);
        } catch(Exception e) {
            LOG.error("Could not send Email.", e);
        }
    }

    private String buildSubject(Alert alert) {
        return "Alert [" + alert.getSubsystem() + "/" + alert.getType().toString() + "]";
    }

    private String buildPlainTextBody(Alert alert) throws URISyntaxException {
        StringBuilder sb = new StringBuilder();

        sb.append("ALERT: " + alert.getMessage()).append("\n\n")
                .append(alert.getDescription()).append("\n\n")
                .append("Link: ").append(buildHTTPURI(alert)).append("\n");

        for (Map.Entry<String, Object> field : alert.getFields().entrySet()) {
            sb.append("\n").append(field.getKey()).append(": ").append(field.getValue());
        }

        return sb.toString();
    }

    @Nullable
    private String buildHTMLTextBody(Alert alert) throws IOException {
        try {
            Map<String, Object> parameters = Maps.newHashMap();
            parameters.put("title", "nzyme Alert");
            parameters.put("alert_summary", alert.getMessage());
            parameters.put("alert_description", alert.getDescription());
            parameters.put("details_link", buildHTTPURI(alert));
            parameters.put("fields", alert.getFields());

            StringWriter out = new StringWriter();
            Template template = this.templateConfig.getTemplate("email/template_basic.ftl");
            template.process(parameters, out);
            return out.toString();
        } catch(Exception e) {
            LOG.error("Could not build HTML text body.", e);
            return null;
        }
    }

    private byte[] loadLogoFile() throws IOException {
        //noinspection UnstableApiUsage
        InputStream resource = getClass().getClassLoader().getResourceAsStream("email/nzyme.png");
        if (resource == null) {
            throw new RuntimeException("Couldn't load nzyme logo file.");
        }

        //noinspection UnstableApiUsage
        return resource.readAllBytes();
    }

    private URI buildHTTPURI(Alert alert) throws URISyntaxException {
        return new URIBuilder(configuration.httpExternalURI())
                .setPath("/alerts/show/" + alert.getUUID())
                .build();
    }

    private static final String WHERE = "alerting.callbacks.[email]";

    public static Configuration parseConfiguration(Config c, String httpExternalUri) throws InvalidConfigurationException, IncompleteConfigurationException {
        // Completeness.
        ConfigurationValidator.expect(c, ConfigurationKeys.TRANSPORT_STRATEGY, WHERE, String.class);
        ConfigurationValidator.expect(c, ConfigurationKeys.HOST, WHERE, String.class);
        ConfigurationValidator.expect(c, ConfigurationKeys.PORT, WHERE, Integer.class);
        ConfigurationValidator.expect(c, ConfigurationKeys.USERNAME, WHERE, String.class);
        ConfigurationValidator.expect(c, ConfigurationKeys.PASSWORD, WHERE, String.class);
        ConfigurationValidator.expect(c, ConfigurationKeys.RECIPIENTS, WHERE, List.class);
        ConfigurationValidator.expect(c, ConfigurationKeys.FROM, WHERE, String.class);
        ConfigurationValidator.expect(c, ConfigurationKeys.SUBJECT_PREFIX, WHERE, String.class);

        // Validity.
        // Transport strategy exists.
        TransportStrategy transportStrategy;
        try {
            transportStrategy = TransportStrategy.valueOf(c.getString(ConfigurationKeys.TRANSPORT_STRATEGY));
        } catch(IllegalArgumentException e) {
            throw new InvalidConfigurationException("Invalid SMTP transport strategy.", e);
        }

        // Recipients are valid.
        List<Recipient> recipients = Lists.newArrayList();
        for (String rec : c.getStringList(ConfigurationKeys.RECIPIENTS)) {
            recipients.add(Tools.parseEmailAddress(rec));
        }

        return Configuration.create(
                transportStrategy,
                c.getString(ConfigurationKeys.HOST),
                c.getInt(ConfigurationKeys.PORT),
                c.getString(ConfigurationKeys.USERNAME),
                c.getString(ConfigurationKeys.PASSWORD),
                recipients,
                Tools.parseEmailAddress(c.getString(ConfigurationKeys.FROM)), // recipient type is ignored
                c.getString(ConfigurationKeys.SUBJECT_PREFIX),
                httpExternalUri
        );
    }

    @AutoValue
    public static abstract class Configuration {

        public abstract TransportStrategy transportStrategy();
        public abstract String host();
        public abstract int port();
        public abstract String username();
        public abstract String password();

        public abstract List<Recipient> recipients();
        public abstract Recipient from();
        public abstract String subjectPrefix();

        public abstract String httpExternalURI();

        public static Configuration create(TransportStrategy transportStrategy, String host, int port, String username, String password, List<Recipient> recipients, Recipient from, String subjectPrefix, String httpExternalURI) {
            return builder()
                    .transportStrategy(transportStrategy)
                    .host(host)
                    .port(port)
                    .username(username)
                    .password(password)
                    .recipients(recipients)
                    .from(from)
                    .subjectPrefix(subjectPrefix)
                    .httpExternalURI(httpExternalURI)
                    .build();
        }

        public static Builder builder() {
            return new AutoValue_EmailCallback_Configuration.Builder();
        }

        @AutoValue.Builder
        public abstract static class Builder {
            public abstract Builder transportStrategy(TransportStrategy transportStrategy);

            public abstract Builder host(String host);

            public abstract Builder port(int port);

            public abstract Builder username(String username);

            public abstract Builder password(String password);

            public abstract Builder recipients(List<Recipient> recipients);

            public abstract Builder from(Recipient from);

            public abstract Builder subjectPrefix(String subjectPrefix);

            public abstract Builder httpExternalURI(String httpExternalURI);

            public abstract Configuration build();
        }
    }

}
