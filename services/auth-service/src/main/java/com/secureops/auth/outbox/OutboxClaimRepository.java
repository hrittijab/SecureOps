package com.secureops.auth.outbox;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Repository
public class OutboxClaimRepository {

    private final JdbcTemplate jdbc;

    public OutboxClaimRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public record ClaimedEvent(
            UUID id,
            String topic,
            String eventKey,
            String payload,
            UUID claimToken
    ) {}

    @Transactional
    public List<ClaimedEvent> claimBatch(int batchSize) {

        UUID claimToken = UUID.randomUUID();

        return jdbc.query(
            """
            WITH candidates AS (
                SELECT id
                FROM security_event_outbox
                WHERE published_at IS NULL
                  AND next_attempt_at <= NOW()
                  AND (
                      claim_token IS NULL
                      OR claimed_until <= NOW()
                  )
                ORDER BY created_at, id
                FOR UPDATE SKIP LOCKED
                LIMIT ?
            )
            UPDATE security_event_outbox AS o
            SET claim_token = ?,
                claimed_until = NOW() + INTERVAL '5 minutes'
            FROM candidates
            WHERE o.id = candidates.id
            RETURNING o.id, o.topic, o.event_key, o.payload
            """,
            (rs, rowNum) -> new ClaimedEvent(
                rs.getObject("id", UUID.class),
                rs.getString("topic"),
                rs.getString("event_key"),
                rs.getString("payload"),
                claimToken
            ),
            batchSize,
            claimToken
        );
    }
}
