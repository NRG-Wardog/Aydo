#pragma once
#include <string>
#include <unordered_set>

namespace SqlRequests {

inline const std::unordered_set<std::string> SKIP_FIELDS = {
    // file handles / pointers we don't care about
    "FileObject",
    "FileKey",
    "IrpPtr",
    "ExtraInfo",
    "KeyHandle",

    // thread / stack internals we don't care about
    "UserStackLimit",
    "StackLimit",
    "UserStackBase",
    "StackBase",
    "TebBase",
    "Affinity",
    "Win32StartAddr",
    "UniqueProcessKey",
    "DirectoryTableBase",

    // image load internals we don't care about
    "ImageBase",
    "ImageSize",
    "DefaultBase",
};

inline const std::unordered_set<std::string> TABLES = {
    // identity/time
    "EventId",
    "EventRecordId",
    "EventTime",

    // meta
    "Source",
    "pid",
    "tid",
    "Provider",
    "Category",
    "AttackTactic",
    "AttackTechnique",
    "AttackSubTechnique",
    "AttackReference",
    "Prevention",
    "Channel",
    "Computer",
    "UserSid",
    "Level",
    "Task",
    "Opcode",
    "Keywords",
    "RuleName",
    "UtcTime",

    // process / image metadata
    "Image",
    "ImageLoaded",
    "SourceImage",
    "TargetImage",
    "ProcessGuid",
    "ParentProcessGuid",
    "ProcessName",
    "ParentProcessName",
    "ParentImage",
    "ParentCommandLine",
    "CurrentDirectory",
    "CommandLine",
    "NewProcessName",
    "OriginalFilename",
    "Hashes",
    "Version",

    // network / IPC
    "IpAddress",
    "LocalAddresses",
    "LocalPorts",
    "RemoteAddresses",
    "RemotePorts",
    "DestinationPort",
    "TransmittedServices",

    // authentication / logon
    "SubjectUserName",
    "SubjectUserSid",
    "TargetUserName",
    "TargetUserSid",
    "OldTargetUserName",
    "NewTargetUserName",
    "TargetDomainName",
    "TargetServerName",
    "LogonProcess",
    "LogonProcessName",
    "LogonType",
    "AuthenticationPackageName",
    "SecurityPackageName",
    "TicketOptions",
    "TicketEncryptionType",
    "GrantedAccess",
    "LogonGuid",
    "LogonId",
    "TerminalSessionId",

    // object / registry / service changes
    "ObjectServer",
    "ObjectType",
    "ObjectName",
    "ObjectDN",
    "ObjectGUID",
    "ObjectClass",
    "ObjectAccessMask",
    "AccessList",
    "AccessMask",
    "Properties",
    "PropertyName",
    "ModifiedProperties_NewValue",
    "Operation",
    "OperationType",
    "Action",
    "RegName",
    "RegValue",
    "RelativeTargetName",
    "TargetObject",
    "TargetInfo",
    "TargetSid",

    // services / Kerberos / delegation
    "ServiceName",
    "ServiceSid",
    "ServicePrincipalNames",
    "AllowedToDelegateTo",

    // policy / config
    "AuditPolicyChanges",
    "SettingType",
    "SettingValue",
    "SettingValueString",
    "AttributeLDAPDisplayName",
    "AttributeValue",
    "Properties_Name",

    // misc sigma fields seen in rule set
    "ApplicationPath",
    "CallerProcessName",
    "ChannelName",
    "CommandLineParams",
    "Details",
    "DeviceDescription",
    "EventType",
    "EventXML_Address",
    "EventXML_Param3",
    "ForwardTo",
    "ForwardAsAttachmentTo",
    "Message",
    "ModifyingApplication",
    "Param1",
    "Param2",
    "Parameters",
    "Parameters_Name",
    "Pattern",
    "Payload",
    "PluginDllName",
    "Process",
    "Status",
    "State",
    "TaskName",
    "UpdateName",
    "UserAccountControl",
    "WorkstationName",
    "_cmdshell",
    "action_id",
    "additional_information",
    "class_type",
    "connections",
    "domain_in_lowercase_xxx",
    "enabled",
    "localport",
    "object_name",
    "param1_lower",
    "pwszAutoConfigUrl",
    "pwszProxy",
    "pwszProxyBypass",
    "statement",

    // housekeeping
    "InsertionTime"};

inline const char *TABLES_CREATE = R"SQL(
CREATE TABLE IF NOT EXISTS Events (
    -- identity/time
    EventId            INTEGER NOT NULL,
    EventRecordId      INTEGER,
    EventTime          DATETIME NOT NULL,

    -- meta
    Source             TEXT DEFAULT 'ETW', 
    pid                INTEGER,
    tid                INTEGER,
    Provider           TEXT,
    Category           TEXT,
    AttackTactic       TEXT,
    AttackTechnique    TEXT,
    AttackSubTechnique TEXT,
    AttackReference    TEXT,
    Prevention         TEXT,
    Channel            TEXT,
    Computer           TEXT,
    UserSid            TEXT,
    Level              INTEGER,
    Task               INTEGER,
    Opcode             INTEGER,
    Keywords           TEXT,
    RuleName           TEXT,
    UtcTime            TEXT,

    -- process / image metadata
    Image              TEXT,
    ImageLoaded        TEXT,
    SourceImage        TEXT,
    TargetImage        TEXT,
    ProcessGuid        TEXT,
    ParentProcessGuid  TEXT,
    ProcessName        TEXT,
    ParentProcessName  TEXT,
    ParentImage        TEXT,
    ParentCommandLine  TEXT,
    CurrentDirectory   TEXT,
    CommandLine        TEXT,
    NewProcessName     TEXT,
    OriginalFilename   TEXT,
    Hashes             TEXT,
    Version            TEXT,

    -- network / IPC
    IpAddress          TEXT,
    LocalAddresses     TEXT,
    LocalPorts         TEXT,
    RemoteAddresses    TEXT,
    RemotePorts        TEXT,
    DestinationPort    TEXT,
    TransmittedServices TEXT,

    -- authentication / logon
    SubjectUserName    TEXT,
    SubjectUserSid     TEXT,
    TargetUserName     TEXT,
    TargetUserSid      TEXT,
    OldTargetUserName  TEXT,
    NewTargetUserName  TEXT,
    TargetDomainName   TEXT,
    TargetServerName   TEXT,
    LogonProcess       TEXT,
    LogonProcessName   TEXT,
    LogonType          TEXT,
    AuthenticationPackageName TEXT,
    SecurityPackageName TEXT,
    TicketOptions      TEXT,
    TicketEncryptionType TEXT,
    GrantedAccess      TEXT,
    LogonGuid          TEXT,
    LogonId            TEXT,
    TerminalSessionId  TEXT,

    -- object / registry / service changes
    ObjectServer       TEXT,
    ObjectType         TEXT,
    ObjectName         TEXT,
    ObjectDN           TEXT,
    ObjectGUID         TEXT,
    ObjectClass        TEXT,       
    ObjectAccessMask   TEXT,
    AccessList         TEXT,
    AccessMask         TEXT,
    Properties         TEXT,
    PropertyName       TEXT,
    ModifiedProperties_NewValue TEXT,
    Operation          TEXT,
    OperationType      TEXT,
    Action             TEXT,
    RegName            TEXT,
    RegValue           TEXT,
    RelativeTargetName TEXT,
    TargetObject       TEXT,
    TargetInfo         TEXT,
    TargetSid          TEXT,

    -- services / Kerberos / delegation
    ServiceName        TEXT,
    ServiceSid         TEXT,
    ServicePrincipalNames TEXT,
    AllowedToDelegateTo TEXT,

    -- policy / config
    AuditPolicyChanges TEXT,
    SettingType        TEXT,
    SettingValue       TEXT,
    SettingValueString TEXT,
    AttributeLDAPDisplayName TEXT,
    AttributeValue     TEXT,
    Properties_Name    TEXT,

    -- misc sigma fields seen in rule set
    ApplicationPath    TEXT,
    CallerProcessName  TEXT,
    ChannelName        TEXT,
    CommandLineParams  TEXT,
    Details            TEXT,
    DeviceDescription  TEXT,
    EventType          TEXT,
    EventXML_Address   TEXT,
    EventXML_Param3    TEXT,
    ForwardTo          TEXT,
    ForwardAsAttachmentTo TEXT,
    Message            TEXT,
    ModifyingApplication TEXT,
    Param1             TEXT,
    Param2             TEXT,
    Parameters         TEXT,
    Parameters_Name    TEXT,
    Pattern            TEXT,
    Payload            TEXT,
    PluginDllName      TEXT,
    Process            TEXT,
    Status             TEXT,
    State              TEXT,
    TaskName           TEXT,
    UpdateName         TEXT,
    UserAccountControl TEXT,
    WorkstationName    TEXT,
    _cmdshell          TEXT,
    action_id          TEXT,
    additional_information TEXT,
    class_type         TEXT,
    connections        TEXT,
    domain_in_lowercase_xxx TEXT,
    enabled            TEXT,
    localport          TEXT,
    object_name        TEXT,
    param1_lower       TEXT,
    pwszAutoConfigUrl  TEXT,
    pwszProxy          TEXT,
    pwszProxyBypass    TEXT,
    statement          TEXT,

    -- housekeeping
    InsertionTime      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_time      ON Events(EventTime);
CREATE INDEX IF NOT EXISTS idx_events_ids       ON Events(EventId, EventRecordId);
CREATE INDEX IF NOT EXISTS idx_events_provider  ON Events(Provider);
CREATE INDEX IF NOT EXISTS idx_events_pid_time  ON Events(pid, EventTime);
CREATE INDEX IF NOT EXISTS idx_events_src_time  ON Events(Source, EventTime);

CREATE TABLE IF NOT EXISTS Findings (
    EventTime      DATETIME NOT NULL,
    Type           TEXT,
    Severity       INTEGER,
    Confidence     INTEGER,
    SourcePid      INTEGER,
    TargetPid      INTEGER,
    Tid            INTEGER,
    EvidenceJson   TEXT,
    AttackTactic       TEXT,
    AttackTechnique    TEXT,
    AttackSubTechnique TEXT,
    AttackReference    TEXT,
    Prevention         TEXT,
    InsertionTime  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_time ON Findings(EventTime);
CREATE INDEX IF NOT EXISTS idx_findings_type ON Findings(Type);
)SQL";

}; // namespace SqlRequests
