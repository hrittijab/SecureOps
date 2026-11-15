package com.secureops.auth.outbox;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
public class SecurityEventOutboxPublisher {

    private final OutboxClaimRepository claims;
    private final JdbcTemplate jdbc;
    private final KafkaTemplate<String, String> kafka;

    @Value("${secureops.outbox.publisher.enabled:true}")
    private boolean enabled;

    public SecurityEventOutboxPublisher(
            OutboxClaimRepository claims,
            JdbcTemplate jdbc,
            KafkaTemplate<String, String> kafka
    ) {
        this.claims = claims;
        this.jdbc = jdbc;
        this.kafka = kafka;
    }

    @Scheduled(
        fixedDelayString = "${secureops.outbox.publisher.fixed-delay-ms:5000}"
    )
    public void publishPending() {

        if (!enabled) {
            return;
        }

        var events = claims.claimBatch(1);

        for (var event : events) {
            try {
                kafka.send(
                    event.topic(),
                    event.eventKey(),
                    event.payload()
                ).get(10, TimeUnit.SECONDS);

                int updated = jdbc.update(
                    """
                    UPDATE security_event_outbox
                    SET published_at = NOW(),
                        attempts = attempts + 1,
                        last_error = NULL,
                        claim_token = NULL,
                        claimed_until = NULL
                    WHERE id = ?
                      AND claim_token = ?
                      AND claimed_until > NOW()
                      AND published_at IS NULL
                    """,
                    event.id(),
                    event.claimToken()
                );

                if (updated != 1) {
                    System.err.println(
                        "Kafka acknowledged event, but outbox claim was lost: "
                        + event.id()
                    );
                }

            } catch (Exception e) {

                String error = e.getMessage();

                if (error == null) {
                    error = e.getClass().getSimpleName();
                }

                if (error.length() > 2000) {
                    error = error.substring(0, 2000);
                }

                jdbc.update(
                    """
                    UPDATE security_event_outbox
                    SET attempts = attempts + 1,
                        last_error = ?,
                        next_attempt_at = NOW() +
                            (
                                LEAST(
                                    300,
                                    POWER(
                                        2,
                                        LEAST(attempts + 1, 8)
                                    )
                                ) * INTERVAL '1 second'
                            ),
                        claim_token = NULL,
                        claimed_until = NULL
                    WHERE id = ?
                      AND claim_token = ?
                      AND claimed_until > NOW()
                      AND published_at IS NULL
                    """,
                    error,
                    event.id(),
                    event.claimToken()
                );
            }
        }
    }
}
