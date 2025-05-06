package com.github.dtreskunov.opentelemetry;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.github.dtreskunov.easyssl.EasySslHelper;
import com.github.dtreskunov.easyssl.EasySslProperties;
import com.github.dtreskunov.easyssl.ext.AwsSecretsManagerProtocolBeans;
import com.google.auto.service.AutoService;

import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporter;
import io.opentelemetry.exporter.otlp.http.metrics.OtlpHttpMetricExporter;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.exporter.otlp.logs.OtlpGrpcLogRecordExporter;
import io.opentelemetry.exporter.otlp.metrics.OtlpGrpcMetricExporter;
import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporter;
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizer;
import io.opentelemetry.sdk.autoconfigure.spi.AutoConfigurationCustomizerProvider;
import io.opentelemetry.sdk.autoconfigure.spi.ConfigProperties;
import lombok.SneakyThrows;

/**
 * This is one of the main entry points for Instrumentation Agent's customizations. It allows
 * configuring the {@link AutoConfigurationCustomizer}. See the {@link
 * #customize(AutoConfigurationCustomizer)} method below.
 *
 * <p>Also see https://github.com/open-telemetry/opentelemetry-java/issues/2022
 *
 * @see AutoConfigurationCustomizerProvider
 */
@AutoService(AutoConfigurationCustomizerProvider.class)
public class InjectEasySsl implements AutoConfigurationCustomizerProvider {

  private EasySslHelper easySslHelper;

  @Override
  public void customize(AutoConfigurationCustomizer autoConfiguration) {
    autoConfiguration.addSpanExporterCustomizer((spanExporter, configProperties) -> {
      if (!isEnabled(configProperties)) {
        return spanExporter;
      }
      if (spanExporter instanceof OtlpHttpSpanExporter) {
        return customize((OtlpHttpSpanExporter) spanExporter, configProperties);
      }
      if (spanExporter instanceof OtlpGrpcSpanExporter) {
        return customize((OtlpGrpcSpanExporter) spanExporter, configProperties);
      }
      return spanExporter;
    });

    autoConfiguration.addMetricExporterCustomizer((metricExporter, configProperties) -> {
      if (!isEnabled(configProperties)) {
        return metricExporter;
      }
      if (metricExporter instanceof OtlpGrpcMetricExporter) {
        return customize((OtlpGrpcMetricExporter) metricExporter, configProperties);
      }
      if (metricExporter instanceof OtlpHttpMetricExporter) {
        return customize((OtlpHttpMetricExporter) metricExporter, configProperties);
      }
      return metricExporter;
    });

    autoConfiguration.addLogRecordExporterCustomizer((logRecordExporter, configProperties) -> {
      if (!isEnabled(configProperties)) {
        return logRecordExporter;
      }
      if (logRecordExporter instanceof OtlpGrpcLogRecordExporter) {
        return customize((OtlpGrpcLogRecordExporter) logRecordExporter, configProperties);
      }
      if (logRecordExporter instanceof OtlpHttpLogRecordExporter) {
        return customize((OtlpHttpLogRecordExporter) logRecordExporter, configProperties);
      }
      return logRecordExporter;
    });
  }

  @SneakyThrows
  private OtlpGrpcLogRecordExporter customize(OtlpGrpcLogRecordExporter exporter, ConfigProperties configProperties) {
    EasySslHelper helper = getEasySslHelper(configProperties);
    return exporter.toBuilder()
      .setSslContext(helper.getSSLContext(), helper.getTrustManager())
      .build();
  }

  @SneakyThrows
  private OtlpHttpLogRecordExporter customize(OtlpHttpLogRecordExporter exporter, ConfigProperties configProperties) {
    EasySslHelper helper = getEasySslHelper(configProperties);
    return exporter.toBuilder()
      .setSslContext(helper.getSSLContext(), helper.getTrustManager())
      .build();
  }

  @SneakyThrows
  private OtlpGrpcMetricExporter customize(OtlpGrpcMetricExporter exporter, ConfigProperties configProperties) {
    EasySslHelper helper = getEasySslHelper(configProperties);
    return exporter.toBuilder()
      .setSslContext(helper.getSSLContext(), helper.getTrustManager())
      .build();
  }

  @SneakyThrows
  private OtlpHttpMetricExporter customize(OtlpHttpMetricExporter exporter, ConfigProperties configProperties) {
    EasySslHelper helper = getEasySslHelper(configProperties);
    return exporter.toBuilder()
      .setSslContext(helper.getSSLContext(), helper.getTrustManager())
      .build();
  }

  @SneakyThrows
  private OtlpGrpcSpanExporter customize(OtlpGrpcSpanExporter exporter, ConfigProperties configProperties) {
    EasySslHelper helper = getEasySslHelper(configProperties);
    return exporter.toBuilder()
      .setSslContext(helper.getSSLContext(), helper.getTrustManager())
      .build();
  }

  @SneakyThrows
  private OtlpHttpSpanExporter customize(OtlpHttpSpanExporter exporter, ConfigProperties configProperties) {
    if (!isEnabled(configProperties)) {
      return exporter;
    }
    EasySslHelper helper = getEasySslHelper(configProperties);
    return exporter.toBuilder()
      .setSslContext(helper.getSSLContext(), helper.getTrustManager())
      .build();
  }

  private static boolean isEnabled(ConfigProperties configProperties) {
    return configProperties.getBoolean("otel.exporter.easyssl.enabled", false);
  }

  @SneakyThrows
  synchronized private EasySslHelper getEasySslHelper(ConfigProperties configProperties) {
    if (easySslHelper == null) {
      AWSSecretsManager secretsManager = AWSSecretsManagerClientBuilder.defaultClient();
      ConfigurableApplicationContext resourceLoader = new StaticApplicationContext();
      resourceLoader.addProtocolResolver(new AwsSecretsManagerProtocolBeans.AwsSecretsManagerProtocolResolver(secretsManager));
      easySslHelper = getEasySslHelper(configProperties, resourceLoader);
    }
    return easySslHelper;
  }

  private static EasySslHelper getEasySslHelper(ConfigProperties configProperties, ResourceLoader resourceLoader) throws Exception {
    EasySslProperties properties = new EasySslProperties();
    Optional
      .ofNullable(configProperties.getString("otel.exporter.easyssl.caCertificate"))
      .ifPresent(caCertificateString -> {
        List<Resource> caCertificates = Stream
          .of(caCertificateString.split(","))
          .map(caCert -> resourceLoader.getResource(caCert.trim()))
          .collect(Collectors.toList());
        properties.setCaCertificate(caCertificates);
      });
        
    Optional
      .ofNullable(configProperties.getString("otel.exporter.easyssl.certificate"))
      .ifPresent(certificateString -> {
        Resource certificate = resourceLoader.getResource(certificateString.trim());
        properties.setCertificate(certificate);
      });

    Optional
      .ofNullable(configProperties.getString("otel.exporter.easyssl.certificateExpirationCheckInterval"))
      .ifPresent(certificateExpirationCheckIntervalString -> {
        Duration certificateExpirationCheckInterval = Duration.parse(certificateExpirationCheckIntervalString);
        properties.setCertificateExpirationCheckInterval(certificateExpirationCheckInterval);
      });

    Optional
      .ofNullable(configProperties.getString("otel.exporter.easyssl.certificateExpirationWarningThreshold"))
      .ifPresent(certificateExpirationWarningThresholdString -> {
        Duration certificateExpirationWarningThreshold = Duration.parse(certificateExpirationWarningThresholdString);
        properties.setCertificateExpirationWarningThreshold(certificateExpirationWarningThreshold);
      });

    Optional
      .ofNullable(configProperties.getString("otel.exporter.easyssl.certificateRevocationList"))
      .ifPresent(certificateRevocationListString -> {
        Resource certificateRevocationList = resourceLoader.getResource(certificateRevocationListString.trim());
        properties.setCertificateRevocationList(certificateRevocationList);
      });
    properties.setEnabled(true);

    Optional
      .ofNullable(configProperties.getString("otel.exporter.easyssl.key"))
      .ifPresent(keyString -> {
        Resource key = resourceLoader.getResource(keyString.trim());
        properties.setKey(key);
      });
    
    Optional
      .ofNullable(configProperties.getString("otel.exporter.easyssl.keyPassword"))
      .ifPresent(keyPasswordString -> {
        properties.setKeyPassword(keyPasswordString);
      });

    Optional
      .ofNullable(configProperties.getString("otel.exporter.easyssl.refreshCommand"))
      .ifPresent(refreshCommandString -> {
        List<String> refreshCommand = Stream
          .of(refreshCommandString.split(","))
          .map(String::trim)
          .collect(Collectors.toList());
        properties.setRefreshCommand(refreshCommand);
      });
      
    Optional
      .ofNullable(configProperties.getString("otel.exporter.easyssl.refreshInterval"))
      .ifPresent(refreshIntervalString -> {
        Duration refreshInterval = Duration.parse(refreshIntervalString);
        properties.setRefreshInterval(refreshInterval);
      });

    Optional
      .ofNullable(configProperties.getString("otel.exporter.easyssl.refreshTimeout"))
      .ifPresent(refreshTimeoutString -> {
        Duration refreshTimeout = Duration.parse(refreshTimeoutString);
        properties.setRefreshTimeout(refreshTimeout);
      });
    
    return new EasySslHelper(properties);
  }
}
