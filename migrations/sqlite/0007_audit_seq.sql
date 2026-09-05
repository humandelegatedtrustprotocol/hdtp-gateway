-- +goose Up
-- No-op for sqlite: AUTOINCREMENT already accepts explicit seq values, which the
-- audit writer supplies because seq participates in the chain hash (SPEC §11.4).
SELECT 1;

-- +goose Down
SELECT 1;
