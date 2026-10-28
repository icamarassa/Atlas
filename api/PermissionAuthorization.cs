using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using MySqlConnector;

namespace AtlasTi.Api;

public static class PermissionCodes
{
    public const string DocumentRead = "document.read";
    public const string DocumentCreate = "document.create";
    public const string DocumentEdit = "document.edit";
    public const string DocumentSubmit = "document.submit";
    public const string DocumentApprove = "document.approve";
    public const string DocumentChangeState = "document.change_state";
    public const string DocumentManage = "document.manage";
    public const string DocumentDelete = "document.delete";
    public const string CatalogManage = "catalog.manage";
    public const string UserView = "user.view";
    public const string UserDelete = "user.delete";
    public const string PermissionManage = "permission.manage";
    public const string MasterRole = "Master";
    public static readonly string[] All = [DocumentRead, DocumentCreate, DocumentEdit, DocumentSubmit, DocumentApprove, DocumentChangeState, DocumentManage, DocumentDelete, CatalogManage, UserView, UserDelete, PermissionManage];
}

public sealed record PermissionRequirement(string Permission) : IAuthorizationRequirement;

public sealed class PermissionAuthorizationHandler(DatabaseConnectionFactory db, ILogger<PermissionAuthorizationHandler> logger)
    : AuthorizationHandler<PermissionRequirement>
{
    public const string PermissionClaim = "atlas_permission";

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        var externalId = context.User.FindFirstValue("oid") ?? context.User.FindFirstValue("sub");
        if (string.IsNullOrWhiteSpace(externalId)) return;

        try
        {
            await using var connection = await db.OpenAsync(CancellationToken.None);
            await using var command = new MySqlCommand("""
                SELECT CASE WHEN EXISTS (
                    SELECT 1 FROM Users u
                    JOIN UserRoles ur ON ur.UserId=u.UserId
                    JOIN RolePermissions rp ON rp.RoleId=ur.RoleId
                    JOIN Permissions p ON p.PermissionId=rp.PermissionId
                    WHERE u.ExternalId=@externalId AND u.IsActive=1 AND p.Code=@permission
                ) THEN 1 ELSE 0 END
                """, connection);
            command.Parameters.Add(new MySqlParameter("@externalId", externalId));
            command.Parameters.Add(new MySqlParameter("@permission", requirement.Permission));
            if (Convert.ToInt32(await command.ExecuteScalarAsync()) == 1)
            {
                if (context.User.Identity is ClaimsIdentity identity && !context.User.HasClaim(PermissionClaim, requirement.Permission))
                    identity.AddClaim(new Claim(PermissionClaim, requirement.Permission));
                context.Succeed(requirement);
            }
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Permission lookup failed for {Permission}.", requirement.Permission);
            // Fail closed: a database or identity lookup failure never grants access.
        }
    }
}
