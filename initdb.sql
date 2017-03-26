CREATE DATABASE cjdnsnode;
CREATE USER cjdnsnode_user WITH PASSWORD 'cjdnsnode_passwd';
GRANT ALL PRIVILEGES ON DATABASE cjdnsnode TO "cjdnsnode_user";
\c cjdnsnode;

DO $body$
BEGIN


CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    senderIpv6 TEXT NOT NULL,
    hash TEXT UNIQUE NOT NULL,
    ts BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS announcements (
    senderIpv6 TEXT NOT NULL,
    messageId INTEGER NOT NULL,
    peerIpv6 TEXT NOT NULL,
    ts BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS messageContent (
    id INTEGER PRIMARY KEY,
    content bytea NOT NULL
);

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "cjdnsnode_user";

DROP FUNCTION IF EXISTS Snode_addMessage(text,text,bigint,bytea,text[]);
CREATE FUNCTION Snode_addMessage(__senderIpv6 TEXT, __hash TEXT, __ts BIGINT, __content bytea, VARIADIC __announcements text[])
    RETURNS void AS $$
    DECLARE
        _messageId INTEGER;
        _announcment TEXT;
    BEGIN
        INSERT INTO messages (id, senderIpv6, hash, ts) VALUES (DEFAULT, __senderIpv6, __hash, __ts) RETURNING id INTO _messageId;
        INSERT INTO messageContent (id, content) VALUES (_messageId, __content);
        FOREACH _announcment IN ARRAY __announcements LOOP
            INSERT INTO announcements (senderIpv6, messageId, peerIpv6, ts)
                VALUES (__senderIpv6, _messageId, _announcement, __ts);
        END LOOP;
    END;
$$ LANGUAGE 'plpgsql';

DROP FUNCTION IF EXISTS Snode_deleteMessage(text);
CREATE FUNCTION Snode_deleteMessage(__hash TEXT)
    RETURNS void AS $$
    DECLARE
        _id INTEGER;
    BEGIN
        SELECT id FROM messages WHERE hash = __hash INTO _id;
        DELETE FROM messageContent WHERE id = _id;
        DELETE FROM anouncements WHERE messageId = _id;
        DELETE FROM messages WHERE id = _id;
    END;
$$ LANGUAGE 'plpgsql';

DROP FUNCTION IF EXISTS Snode_garbageCollect(BIGINT);
CREATE FUNCTION Snode_garbageCollect(__earliestValidTs BIGINT)
    RETURNS void AS $$
    DECLARE
    BEGIN
        DELETE FROM announcements WHERE ts < __earliestValidTs;
        DELETE FROM messageContent WHERE id IN (
            SELECT id FROM messages WHERE ts < __earliestValidTs
        );
        DELETE FROM messages WHERE ts < __earliestValidTs;
    END;
$$ LANGUAGE 'plpgsql';

/*
DROP FUNCTION IF EXISTS Snode_expiredMessageIDs(bigint);
CREATE FUNCTION Snode_expiredMessageIDs(__tsLimit BIGINT, __oldestValidTs BIGINT)
    RETURNS SETOF INT AS $$
    DECLARE
        _ipv6 TEXT;
        _annRecord RECORD;
        _maxTs BIGINT;
    BEGIN
        DROP TABLE IF EXISTS Snode_expiredMessageIDs_expired;
        DROP TABLE IF EXISTS Snode_expiredMessageIDs_allForNode;
        DROP TABLE IF EXISTS Snode_expiredMessageIDs_expiredForNode;

        CREATE TEMP TABLE Snode_expiredMessageIDs_expired (id INT PRIMARY KEY) ON COMMIT DROP;
        FOR _ipv6 IN
            SELECT DISTINCT senderIpv6 FROM messages;
        LOOP
            CREATE TEMP TABLE Snode_expiredMessageIDs_allForNode (id INT PRIMARY KEY, ts BIGINT)
                ON COMMIT DROP
                AS SELECT id, ts FROM messages WHERE senderIpv6 = _ipv6;
            SELECT id FROM Snode_expiredMessageIDs_allForNode ORDER BY ts DESC LIMIT 1 INTO _maxTs;
            CREATE TEMP TABLE Snode_expiredMessageIDs_expiredForNode (id INT PRIMARY KEY)
                ON COMMIT DROP;
            INSERT INTO Snode_expiredMessageIDs_expiredForNode (id)
                SELECT id FROM Snode_expiredMessageIDs_allForNode WHERE
                    (ts < (_maxTs - __tsLimit) OR ts < __oldestValidTs);

            FOR _annRecord IN
                SELECT DISTINCT ON (peerIpv6) * FROM announcements
                    WHERE
        END LOOP;



        RETURN QUERY SELECT id FROM messages WHERE id NOT IN (
            SELECT DISTINCT ON (peerIpv6) messageId FROM announcements WHERE ts > __expirationTs GROUP BY peerIpv6 ORDER BY ts DESC
        );
    END
$$ LANGUAGE 'plpgsql';

DROP FUNCTION IF EXISTS Snode_expiredMessageHashes(bigint);
CREATE FUNCTION Snode_expiredMessageHashes(__expirationTs BIGINT)
    RETURNS SETOF TEXT AS $$
    BEGIN
        RETURN QUERY SELECT hash FROM messages WHERE id IN (SELECT Snode_expiredMessageIDs(__expirationTs));
    END
$$ LANGUAGE 'plpgsql';

DROP FUNCTION IF EXISTS Snode_cleanExpiredMessages(bigint);
CREATE FUNCTION Snode_cleanExpiredMessages(__expirationTs BIGINT)
    RETURNS void AS $$
    BEGIN
        CREATE TEMP TABLE Snode_cleanExpiredMessages_ids AS SELECT Snode_expiredMessageIDs(__expirationTs);
        DELETE FROM messageContent WHERE id IN (SELECT * FROM Snode_cleanExpiredMessages_ids);
        DELETE FROM announcements WHERE messageId IN (SELECT * FROM Snode_cleanExpiredMessages_ids);
        DELETE FROM messages WHERE id IN (SELECT * FROM Snode_cleanExpiredMessages_ids);
        DROP TABLE Snode_cleanExpiredMessages_ids;
    END
$$ LANGUAGE 'plpgsql';

DROP FUNCTION IF EXISTS Snode_getPeerings();
CREATE FUNCTION Snode_getPeerings()
    RETURNS TABLE (node TEXT, reachableBy TEXT) AS $$
    BEGIN
        RETURN QUERY SELECT mes.senderIpv6, ann.peerIpv6 FROM messages AS mes, announcements AS ann WHERE ann.messageId = mes.id;
    END
$$ LANGUAGE 'plpgsql';
*/


END;
$body$;
