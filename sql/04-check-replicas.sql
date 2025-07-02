SELECT
    name as availability_group,
    replica_server_name as host,
    rs.synchronization_health_desc AS sync_health,  
    rs.synchronization_state_desc as sync_state,  
    rs.database_state_desc as db_state,
    CASE WHEN (primary_replica  = replica_server_name) THEN 'PRIMARY' ELSE  'SECONDARY' END AS [replica_role],
    failover_mode_desc
FROM
    sys.availability_groups g
    INNER JOIN sys.availability_replicas r ON g.group_id = r.group_id
    INNER JOIN sys.dm_hadr_database_replica_states rs on rs.replica_id = r.replica_id
    INNER JOIN sys.dm_hadr_availability_group_states s ON g.group_id = s.group_id
ORDER BY host