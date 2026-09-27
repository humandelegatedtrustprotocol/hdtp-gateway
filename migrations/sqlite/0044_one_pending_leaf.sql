-- +goose Up
-- One pending signing request per identity (PACT sec. 9.1): a new request replaces the last. The
-- replacement was three statements outside a transaction, so two requests made together could
-- each find nothing to replace and both insert. The request is one transaction now, and this index
-- makes a second pending row impossible. A database that already raced keeps its newest request.
DELETE FROM leaves WHERE state = 'pending' AND EXISTS (
    SELECT 1 FROM leaves newer
    WHERE newer.account_id = leaves.account_id AND newer.state = 'pending'
      AND (newer.created_at > leaves.created_at OR (newer.created_at = leaves.created_at AND newer.kid > leaves.kid))
);
CREATE UNIQUE INDEX leaves_one_pending ON leaves(account_id) WHERE state = 'pending';

-- +goose Down
DROP INDEX leaves_one_pending;
