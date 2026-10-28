namespace AtlasTi.Api;

public sealed record DocumentCreate(string Title, string? Summary, string DocumentType, int CategoryId, int? SystemId, string? Content, string[] Tags);
public sealed record LoginRequest(string Username, string Password);
public sealed record DocumentUpdate(string Title, string? Summary, string DocumentType, int CategoryId, int? SystemId, string[] Tags);
public sealed record VersionCreate(string ChangeSummary, string? Content, string VersionType = "minor");
public sealed record ApprovalRequest(string? Comment);
public sealed record ApprovalDecision(string Decision, string? Comment);
public sealed record StateChange(string State, string? Reason);
public sealed record UserUpsert(string ExternalId, string DisplayName, string Email, string[] Roles, bool IsActive = true);
public sealed record RolePermissionsUpdate(string[] Permissions);
public sealed record RoleUpsert(string Name, string? Description, string[]? Permissions = null);
public sealed record LdapRoleGroupMapping(string GroupDn, string RoleName);
public sealed record LdapConnectionTestRequest(string PrimaryHost, string? SecondaryHost, int Port, string? BaseDn, string? BindUser, string? BindPassword);
public sealed record LdapSettingsUpdate(string PrimaryHost, string? SecondaryHost, int Port, string UserIdFormat, string BootstrapAdminExternalId, string? BaseDn, string LoginAttribute, string? BindUser, string? BindPassword, string? AdminGroupDn, LdapRoleGroupMapping[]? GroupMappings = null);
public sealed record CategoryUpdate(string Name, string? Slug, string? Description);
public sealed record SystemUpdate(string Name, string? OwnerTeam, string? Description);
public sealed record PasswordChangeRequest(string CurrentPassword, string NewPassword);

public sealed record DocumentVisibilityUpdate(bool Hidden);
public sealed record DocumentAttributionUpdate(string OwnerExternalId, long? ApprovalId, string? RequestedByExternalId);
public sealed record DocumentScopeRuleUpdate(int? CategoryId, string? DocumentType);
public sealed record DocumentScopeUpdate(DocumentScopeRuleUpdate[] Rules);
