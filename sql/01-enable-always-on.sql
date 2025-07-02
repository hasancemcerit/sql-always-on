USE [master]
GO

IF EXISTS (SELECT name FROM sys.endpoints WHERE name = 'Hadr_endpoint')
BEGIN
	DROP ENDPOINT Hadr_endpoint
END

CREATE ENDPOINT [Hadr_endpoint] 
	AS TCP (LISTENER_PORT = 5022)
	FOR DATA_MIRRORING (ROLE = ALL, ENCRYPTION = REQUIRED ALGORITHM AES)
GO

IF (SELECT state FROM sys.endpoints WHERE name = N'Hadr_endpoint') <> 0
BEGIN
	ALTER ENDPOINT [Hadr_endpoint] STATE = STARTED
END
GO

GRANT CONNECT ON ENDPOINT::[Hadr_endpoint] TO [SQLDEMO\Administrator]
GO

IF EXISTS(SELECT * FROM sys.server_event_sessions WHERE name='AlwaysOn_health')
BEGIN
  ALTER EVENT SESSION [AlwaysOn_health] ON SERVER WITH (STARTUP_STATE=ON);
END

IF NOT EXISTS(SELECT * FROM sys.dm_xe_sessions WHERE name='AlwaysOn_health')
BEGIN
  ALTER EVENT SESSION [AlwaysOn_health] ON SERVER STATE=START;
END
GO
-- Check if the endpoint is created
SELECT @@SERVERNAME AS host, name, SUSER_NAME(principal_id) AS owner, type_desc
FROM sys.endpoints WHERE name = 'Hadr_endpoint'