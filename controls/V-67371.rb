control "V-67371" do
  title "Database objects (including but not limited to tables, indexes,
storage, stored procedures, functions, triggers, links to software external to
SQL Server, etc.) must be owned by database/DBMS principals authorized for
ownership."
  desc  "Within the database, object ownership implies full privileges to the
owned object, including the privilege to assign access to the owned objects to
other subjects. Database functions and procedures can be coded using definer's
rights. This allows anyone who utilizes the object to perform the actions if
they were the owner. If not properly managed, this can lead to privileged
actions being taken by unauthorized individuals.

    Conversely, if critical tables or other objects rely on unauthorized owner
accounts, these objects may be lost when an account is removed.
  "
  impact 0.7
  tag "gtitle": "SRG-APP-000133-DB-000200"
  tag "gid": "V-67371"
  tag "rid": "SV-81861r1_rule"
  tag "stig_id": "SQL4-00-015600"
  tag "fix_id": "F-73483r1_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review system documentation to identify SQL Server accounts
authorized to own database objects.

If the SQL Server database ownership list does not exist or needs to be
updated, this is a finding.

The view STIG.database_permissions, included in the supplemental file,
Permissions.sql, can be of use in making this determination:
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
        --  Complete the \"NOT IN\" list with the names of user accounts
authorized for ownership.
;
If any of the listed owners is not authorized, this is a finding."
  tag "fix": "Add and/or update system documentation to include any accounts
authorized for object ownership and remove any account not authorized.

To change the schema owning a database object in SQL Server, use this code:
USE <database name>;
GO
ALTER SCHEMA <name of new schema> TRANSFER <name of old schema>.<object name>;
GO

Caution:  this can break code.  This Fix should be implemented in conjunction
with corrections to such code.  Test before deploying in production.  Deploy
during a scheduled maintenance window."
end

