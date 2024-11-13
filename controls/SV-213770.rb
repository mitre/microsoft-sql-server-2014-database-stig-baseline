control 'SV-213770' do
  title 'Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to SQL Server, etc.) must be owned by database/DBMS principals authorized for ownership.'
  desc "Within the database, object ownership implies full privileges to the owned object, including the privilege to assign access to the owned objects to other subjects. Database functions and procedures can be coded using definer's rights. This allows anyone who utilizes the object to perform the actions if they were the owner. If not properly managed, this can lead to privileged actions being taken by unauthorized individuals.

Conversely, if critical tables or other objects rely on unauthorized owner accounts, these objects may be lost when an account is removed."
  desc 'check', %q(Review system documentation to identify SQL Server accounts authorized to own database objects.

If the SQL Server database ownership list does not exist or needs to be updated, this is a finding.

The view STIG.database_permissions, included in the supplemental file, Permissions.sql, can be of use in making this determination:
USE <database name>;
GO
SELECT DISTINCT
        S.[Schema/Owner] AS  [Owner],
        O.[Schema/Owner] AS [Schema],
        O.[Securable]
FROM
        STIG.database_permissions O
        INNER JOIN STIG.database_permissions S
                ON S.[Securable] = O.[Schema/Owner]
                AND O.[Securable Type or Class] = 'OBJECT_OR_COLUMN'
                AND S.[Securable Type or Class] = 'SCHEMA'
WHERE
        S.[Schema/Owner] NOT IN ('dbo', 'sys', 'INFORMATION_SCHEMA' ... )
        --  Complete the "NOT IN" list with the names of user accounts authorized for ownership.
;
If any of the listed owners is not authorized, this is a finding.)
  desc 'fix', 'Add and/or update system documentation to include any accounts authorized for object ownership and remove any account not authorized.

To change the schema owning a database object in SQL Server, use this code:
USE <database name>;
GO
ALTER SCHEMA <name of new schema> TRANSFER <name of old schema>.<object name>;
GO

Caution:  this can break code.  This Fix should be implemented in conjunction with corrections to such code.  Test before deploying in production.  Deploy during a scheduled maintenance window.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Database'
  tag check_id: 'C-14990r312388_chk'
  tag severity: 'medium'
  tag gid: 'V-213770'
  tag rid: 'SV-213770r960960_rule'
  tag stig_id: 'SQL4-00-015600'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-14988r312389_fix'
  tag 'documentable'
  tag legacy: ['SV-81861', 'V-67371']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  # The query in check text is assumes the presence of STIG schema as supplied
  # with the STIG supplemental. The below query ( taken from 2016 MSSQL STIG)
  # will work without STIG supplemental schema.

  query = %{
      ;WITH OBJECTS_CTE
           AS (SELECT O.NAME,
                      O.TYPE_DESC,
                      CASE
                        WHEN O.PRINCIPAL_ID IS NULL THEN S.PRINCIPAL_ID
                        ELSE O.PRINCIPAL_ID
                      END AS PRINCIPAL_ID
               FROM   SYS.OBJECTS O
                      INNER JOIN SYS.SCHEMAS S
                              ON O.SCHEMA_ID = S.SCHEMA_ID
               WHERE  O.IS_MS_SHIPPED = 0)
      SELECT CTE.NAME,
             CTE.TYPE_DESC,
             DP.NAME AS OBJECTOWNER
      FROM   OBJECTS_CTE CTE
             INNER JOIN SYS.DATABASE_PRINCIPALS DP
                     ON CTE.PRINCIPAL_ID = DP.PRINCIPAL_ID
      ORDER  BY DP.NAME,
                CTE.NAME
  }

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'),
                              db_name: input('db_name'))

  describe "Authorized users for Database: #{input('db_name')}" do
    subject { sql_session.query(query).column('objectowner').uniq }
    it { should cmp input('authorized_principals') }
  end
end
