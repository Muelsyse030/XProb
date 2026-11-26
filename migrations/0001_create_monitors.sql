CREATE TABLE monitors (
    id BIGINT NOT NULL AUTO_INCREMENT,
    workspace_id VARCHAR(255) COLLATE utf8mb4_0900_bin NOT NULL,
    name TEXT NOT NULL,
    status VARCHAR(16) NOT NULL,
    PRIMARY KEY (id),
    KEY idx_monitors_workspace_id (workspace_id, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
