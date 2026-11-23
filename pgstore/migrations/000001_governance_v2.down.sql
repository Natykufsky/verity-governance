DROP TRIGGER IF EXISTS trg_gov_state_guard ON governance_request;
DROP FUNCTION IF EXISTS gov_state_guard();
DROP TABLE IF EXISTS governance_outbox;
DROP TABLE IF EXISTS governance_request_approval;
DROP TABLE IF EXISTS governance_request;
DROP TABLE IF EXISTS governance_policy_rule;
DROP TYPE IF EXISTS gov_state;

