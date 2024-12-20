control 'SV-213793' do
  title 'SQL Server must generate Trace or Audit records when unsuccessful attempts to modify privileges/permissions via locally-defined security objects occur.'
  desc "Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected.

In SQL Server, there is no distinction between modification of permissions and granting or dropping them.  However, native SQL Server security functionality may be supplemented with application-specific tables and logic, in which case the following actions on these tables and procedures/triggers/functions are also relevant:
UPDATE
EXECUTE

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

Use of SQL Server Audit is recommended.  All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014.  It is not available at the database level in other editions.  For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being.  Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.

Use of SQL Server Audit's SCHEMA_OBJECT_ACCESS_GROUP causes capture of all accesses, successful and otherwise, to the system views (and all other schema-scoped objects).  The [Succeeded] column in the audit output indicates the success or failure of the attempted action.  Be aware, however, that it may report True in some cases where one would intuitively expect False.  For example, SELECT 1/0 FROM SYS.ALL_OBJECTS will appear in the audit trail as successful, if the user has permission to perform that action, even though it contains an invalid expression.  Some other actions that one would consider failures (such as selecting from a table that does not exist) may not appear at all."
  desc 'check', %q(Obtain the list of locally-defined security tables, procedures and functions that require tracking.  If there are none, this is not a finding.

If neither SQL Server Audit nor SQL Server Trace is in use for audit purposes, this is a finding.

If SQL Server Trace is in use for audit purposes, review the locally-defined security tables for the existence of triggers to raise a custom event on each Update operation.  If such triggers are not present, this is a finding.

Verify  that all required events are being audited.  From the query prompt:
SELECT * FROM sys.traces;

All currently defined traces for the SQL server instance will be listed. If no traces are returned, this is a finding.

Determine the trace(s) being used for the auditing requirement.
In the following, replace # with a trace ID being used for the auditing requirements.
From the query prompt:
SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(#);

The following required event IDs should be among those listed; if not, this is a finding:

42  -- SP:Starting
43  -- SP:Completed
82-91  -- User-defined Event
162  -- User error message


If SQL Server Audit is in use, proceed as follows.

Verify that all EXECUTE actions on locally-defined permissions-related procedures are being audited.  If not, this is a finding.

The basic SQL Server Audit configuration provided in the supplemental file Audit.sql uses the broad, server-level audit action group SCHEMA_OBJECT_ACCESS_GROUP for this purpose.  SQL Server Audit's flexibility makes other techniques possible.  If an alternative technique is in use and demonstrated effective, this is not a finding.

Determine the name(s) of the server audit specification(s) in use.

To look at audits and audit specifications, in Management Studio's object explorer, expand
<server name> >> Security >> Audits
and
<server name> >> Security >> Server Audit Specifications.
Also,
<server name> >> Databases >> <database name> >> Security >> Database Audit Specifications.

Alternatively, review the contents of the system views with "audit" in their names.

Run the following to verify that all UPDATE and EXECUTE actions on any locally-defined permissions tables, procedures and functions are being audited:
USE [master];
GO
SELECT * FROM sys.server_audit_specification_details WHERE server_specification_id =
(SELECT server_specification_id FROM sys.server_audit_specifications WHERE [name] = '<server_audit_specification_name>')
AND audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP';

If no row is returned, this is a finding.

If the audited_result column is not "FAILURE" or "SUCCESS AND FAILURE", this is a finding.)
  desc 'fix', 'Where SQL Server Trace is in use, define  and enable a trace that captures all auditable events.  The script provided in the supplemental file Trace.sql can be used to do this.

Add blocks of code to Trace.sql for each custom event class (integers in the range 82-91; the same event class may be used for all such triggers) used in these triggers.

Create triggers to raise a custom event on each locally-defined security table that requires tracking of Insert-Update-Delete operations.  The examples provided in the supplemental file CustomTraceEvents.sql can serve as the basis for these.

Execute Trace.sql.

Where SQL Server Audit is in use, design and deploy a SQL Server Audit that captures all auditable events.  The script provided in the supplemental file Audit.sql can be used for this.

Alternatively, to add the necessary data capture to an existing server audit specification, run the script:
USE [master];
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE = OFF);
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> ADD (SCHEMA_OBJECT_ACCESS_GROUP);
GO
ALTER SERVER AUDIT SPECIFICATION <server_audit_specification_name> WITH (STATE = ON);
GO'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Database'
  tag check_id: 'C-15013r312457_chk'
  tag severity: 'medium'
  tag gid: 'V-213793'
  tag rid: 'SV-213793r961800_rule'
  tag stig_id: 'SQL4-00-036300'
  tag gtitle: 'SRG-APP-000495-DB-000329'
  tag fix_id: 'F-15011r312458_fix'
  tag 'documentable'
  tag legacy: ['SV-81909', 'V-67419']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  query_traces = %(
    SELECT * FROM sys.traces
  )
  query_trace_eventinfo = %{
    SELECT DISTINCT(eventid) FROM sys.fn_trace_geteventinfo(%<trace_id>s);
  }

  query_audits = %(
    SELECT server_specification_id,
           audit_action_name,
           audited_result
    FROM   sys.server_audit_specification_details
    WHERE  audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP';
  )

  server_trace_implemented = input('server_trace_implemented')
  server_audit_implemented = input('server_audit_implemented')

  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'),
                              db_name: input('db_name'))

  describe.one do
    describe 'SQL Server Trace is in use for audit purposes' do
      subject { server_trace_implemented }
      it { should be true }
    end

    describe 'SQL Server Audit is in use for audit purposes' do
      subject { server_audit_implemented }
      it { should be true }
    end
  end

  if server_trace_implemented
    describe 'List defined traces for the SQL server instance' do
      subject { sql_session.query(query_traces) }
      it { should_not be_empty }
    end

    trace_ids = sql_session.query(query_traces).column('id')
    describe.one do
      trace_ids.each do |trace_id|
        found_events = sql_session.query(format(query_trace_eventinfo, trace_id: trace_id)).column('eventid')
        describe "EventsIDs in Trace ID:#{trace_id}" do
          subject { found_events }
          it { should include '42' }
          it { should include '43' }
          its('to_s') { should match(/"82"|"83"|"84"|"85"|"86"|"87"|"88"|"89"|"90"|"91"/) }
          it { should include '162' }
        end
      end
    end
  end

  if server_audit_implemented
    describe 'SQL Server Audit:' do
      describe 'Defined Audits with Audit Action SCHEMA_OBJECT_ACCESS_GROUP' do
        subject { sql_session.query(query_audits) }
        it { should_not be_empty }
      end
      describe 'Audited Result for Defined Audit Actions' do
        subject { sql_session.query(query_audits).column('audited_result').uniq.to_s }
        it { should match(/SUCCESS AND FAILURE|FAILURE/) }
      end
    end
  end
end
