using System.Data;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using AtlasTi.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using MySqlConnector;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.FileProviders;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);
var configuredKeyPath = builder.Configuration["DataProtection:KeysPath"] ?? Path.Combine("App_Data", "DataProtectionKeys");
var keyPath = Path.IsPathRooted(configuredKeyPath) ? configuredKeyPath : Path.Combine(builder.Environment.ContentRootPath, configuredKeyPath);
Directory.CreateDirectory(keyPath);
var dataProtection = builder.Services.AddDataProtection().SetApplicationName("AtlasTi").PersistKeysToFileSystem(new DirectoryInfo(keyPath));
if (OperatingSystem.IsWindows()) dataProtection.ProtectKeysWithDpapi();
else if (!string.IsNullOrWhiteSpace(builder.Configuration["DataProtection:KeyEncryptionCertificatePath"]))
{
    var certificate = X509CertificateLoader.LoadPkcs12FromFile(
        builder.Configuration["DataProtection:KeyEncryptionCertificatePath"]!,
        builder.Configuration["DataProtection:KeyEncryptionCertificatePassword"]);
    if (!certificate.HasPrivateKey) throw new InvalidOperationException("O certificado de proteção das chaves precisa conter a chave privada.");
    dataProtection.ProtectKeysWithCertificate(certificate);
}
else if (!builder.Environment.IsDevelopment())
    throw new InvalidOperationException("Configure DataProtection:KeyEncryptionCertificatePath e a senha do certificado antes de iniciar o Atlas TI em Linux/produção.");
builder.Services.AddSingleton(new DatabaseConnectionFactory(builder.Configuration.GetConnectionString("AtlasTi")
    ?? throw new InvalidOperationException("Configure ConnectionStrings:AtlasTi.")));
builder.Services.AddSingleton<DocumentFileStore>();
builder.Services.AddSingleton<LdapAuthenticator>();
var tokenIssuer = new JwtTokenIssuer(builder.Configuration);
builder.Services.AddSingleton(tokenIssuer);
builder.Services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = tokenIssuer.ValidationParameters;
    });
builder.Services.AddAuthorization(options =>
{
    foreach (var permission in PermissionCodes.All)
        options.AddPolicy(permission, policy => policy.RequireAuthenticatedUser()
            .AddRequirements(new PermissionRequirement(permission)));
});
builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
{
    var origins = builder.Configuration.GetSection("Cors:Origins").Get<string[]>() ?? [];
    if (origins.Length > 0) policy.WithOrigins(origins);
    policy.AllowAnyHeader().AllowAnyMethod();
}));
builder.Services.AddRateLimiter(options => options.AddPolicy("ldap-login", context =>
    RateLimitPartition.GetFixedWindowLimiter(
        context.Request.Headers["X-Real-IP"].FirstOrDefault() ?? context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 5, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true })));
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization", Type = SecuritySchemeType.Http, Scheme = "bearer", BearerFormat = "JWT", In = ParameterLocation.Header,
        Description = "Token de acesso emitido pelo endpoint /api/auth/login após autenticação LDAPS."
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { new OpenApiSecurityScheme { Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" } }, Array.Empty<string>() }
    });
});

var app = builder.Build();
if (app.Configuration.GetValue<bool>("DatabaseBootstrap:InitializeOnStartup"))
    await DatabaseBootstrapper.InitializeAsync(app.Configuration, app.Logger);
var staticRoot = Path.Combine(AppContext.BaseDirectory, "wwwroot");
if (Directory.Exists(staticRoot))
{
    var files = new PhysicalFileProvider(staticRoot);
    app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = files });
    app.UseStaticFiles(new StaticFileOptions { FileProvider = files });
}
app.UseExceptionHandler(handler => handler.Run(async context =>
{
    context.Response.StatusCode = StatusCodes.Status500InternalServerError;
    context.Response.ContentType = "application/problem+json";
    await context.Response.WriteAsJsonAsync(new ProblemDetails
    {
        Status = 500,
        Title = "Ocorreu um erro ao processar a solicitação.",
        Instance = context.Request.Path
    });
}));
app.UseRouting();
app.UseCors();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health/live", () => Results.Ok(new { status = "ok" }));
app.MapGet("/health/ready", async (DatabaseConnectionFactory db, CancellationToken ct) =>
{
    await using var connection = db.Create();
    await connection.OpenAsync(ct);
    await using var command = new MySqlCommand("SELECT 1", connection);
    await command.ExecuteScalarAsync(ct);
    return Results.Ok(new { status = "ready", database = "connected" });
});

var api = app.MapGroup("/api");
api.MapPost("/account/password", async (PasswordChangeRequest request, ClaimsPrincipal actor, LdapAuthenticator ldap, IDataProtectionProvider protection, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    if (string.IsNullOrEmpty(request.CurrentPassword) || string.IsNullOrWhiteSpace(request.NewPassword) || request.NewPassword.Length < 8)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["password"] = ["Informe a senha atual e uma nova senha com pelo menos 8 caracteres."] });
    var settings = await ReadLdapSettingsAsync(db, ct);
    if (settings is null || string.IsNullOrWhiteSpace(settings.BindUser) || string.IsNullOrWhiteSpace(settings.BindPasswordProtected) || string.IsNullOrWhiteSpace(settings.BaseDn))
        return Results.Problem("A consulta LDAP para alteração de senha ainda não foi configurada pelo administrador.", statusCode: StatusCodes.Status503ServiceUnavailable);
    string bindPassword;
    try { bindPassword = protection.CreateProtector("AtlasTi.Ldap.BindPassword.v1").Unprotect(settings.BindPasswordProtected); }
    catch (System.Security.Cryptography.CryptographicException) { return Results.Problem("Não foi possível descriptografar a credencial LDAP. Verifique a chave de proteção persistida da API.", statusCode: StatusCodes.Status503ServiceUnavailable); }
    var username = actor.FindFirstValue("preferred_username") ?? actor.FindFirstValue("sub");
    if (string.IsNullOrWhiteSpace(username) || !ldap.ChangePassword(username, request.CurrentPassword, request.NewPassword, bindPassword, settings))
        return Results.BadRequest(new { error = "Não foi possível alterar a senha. Confira a senha atual e a política do diretório." });
    return Results.Ok(new { message = "Senha alterada no diretório." });
}).RequireAuthorization();
api.MapPost("/auth/login", async (LoginRequest request, LdapAuthenticator ldap, JwtTokenIssuer issuer, IDataProtectionProvider protection, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var ldapSettings = await ReadLdapSettingsAsync(db, ct);
    if (ldapSettings is null || string.IsNullOrWhiteSpace(ldapSettings.PrimaryHost))
        return Results.Problem("A autenticação LDAP não está configurada.", statusCode: StatusCodes.Status503ServiceUnavailable);
    if (!ldap.ValidateCredentials(request.Username, request.Password, ldapSettings, out var subject) || subject is null)
        return Results.Unauthorized();
    var typedLogin = request.Username.Trim();
    // Provisionamento JIT: com a conta de consulta configurada, o usuário passa a ser identificado sempre pela mesma chave
    // (sAMAccountName em minúsculas) e recebe nome/e-mail reais do AD. Sem isso, "ana", "ana@dominio" e "DOM\ana" viram
    // três usuários diferentes: autoria e papéis se dividem e a regra "quem enviou não aprova" pode ser contornada.
    string? bindPassword = null;
    if (!string.IsNullOrWhiteSpace(ldapSettings.BindUser) && !string.IsNullOrWhiteSpace(ldapSettings.BindPasswordProtected) && !string.IsNullOrWhiteSpace(ldapSettings.BaseDn))
    {
        try { bindPassword = protection.CreateProtector("AtlasTi.Ldap.BindPassword.v1").Unprotect(ldapSettings.BindPasswordProtected); }
        catch (System.Security.Cryptography.CryptographicException) { app.Logger.LogWarning("Não foi possível descriptografar a credencial LDAP de consulta; o provisionamento JIT não será aplicado neste login."); }
    }
    var canonicalSubject = subject;
    var displayName = typedLogin;
    string? directoryMail = null;
    if (bindPassword is not null)
    {
        var profile = ldap.ReadUserProfile(typedLogin, bindPassword, ldapSettings);
        if (profile.Success)
        {
            var samAccount = profile.Attributes.GetValueOrDefault("sAMAccountName");
            if (!string.IsNullOrWhiteSpace(samAccount)) canonicalSubject = samAccount.Trim().ToLowerInvariant();
            var fullName = profile.Attributes.GetValueOrDefault("displayName");
            if (string.IsNullOrWhiteSpace(fullName))
                fullName = string.Join(' ', new[] { profile.Attributes.GetValueOrDefault("givenName"), profile.Attributes.GetValueOrDefault("sn") }.Where(x => !string.IsNullOrWhiteSpace(x)));
            if (!string.IsNullOrWhiteSpace(fullName)) displayName = fullName.Trim();
            directoryMail = profile.Attributes.GetValueOrDefault("mail");
        }
    }
    // Quem já existe no Atlas TI com outra forma de login (UPN, DOM\ana ou o texto digitado) continua sendo o mesmo usuário:
    // usa-se o registro mais antigo, sem renomear nem duplicar autoria, papéis e e-mail.
    var knownKeys = new[] { canonicalSubject, subject, typedLogin }.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    var existingKey = (await QueryAsync(db, $"SELECT ExternalId FROM Users WHERE ExternalId IN ({string.Join(',', knownKeys.Select((_, index) => $"@k{index}"))}) ORDER BY UserId LIMIT 1", knownKeys.Select((key, index) => P($"@k{index}", key)).ToArray(), r => r.GetString(0), ct)).FirstOrDefault();
    if (existingKey is not null) canonicalSubject = existingKey;
    var claims = new List<Claim> { new("sub", canonicalSubject), new("name", displayName), new("preferred_username", typedLogin) };
    if (!string.IsNullOrWhiteSpace(directoryMail)) claims.Add(new Claim("email", directoryMail.Trim()));
    var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "ldaps"));
    var userId = await EnsureUserAsync(db, principal, ct, refreshProfile: true);
    await using var connection = await db.OpenAsync(ct);
    await using var activeCheck = new MySqlCommand("SELECT IsActive FROM Users WHERE UserId=@id", connection);
    activeCheck.Parameters.Add(P("@id", userId));
    if (await activeCheck.ExecuteScalarAsync(ct) is not true) return Results.Problem("Sua conta está desativada ou foi excluída do Atlas TI. Procure a equipe de TI.", statusCode: StatusCodes.Status403Forbidden);
    var roleMappings = await QueryAsync(db, "SELECT GroupDn,RoleName FROM LdapRoleGroupMappings ORDER BY MappingId", null, r => new LdapRoleGroupMapping(r.GetString(0), r.GetString(1)), ct);
    if (roleMappings.Count > 0)
    {
        if (bindPassword is null)
            return Results.Problem("A atribuição JIT por grupo requer Base DN, usuário e senha protegida da conta de consulta LDAPS (e a chave de proteção da API para lê-la).", statusCode: StatusCodes.Status503ServiceUnavailable);
        var assignedRoles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var mapping in roleMappings)
        {
            var membership = ldap.IsDirectMemberOfGroup(typedLogin, bindPassword, ldapSettings with { AdminGroupDn = mapping.GroupDn });
            if (!membership.Success) return Results.Problem("Não foi possível consultar os grupos JIT no diretório; o login foi interrompido para evitar permissões incorretas.", statusCode: StatusCodes.Status503ServiceUnavailable);
            if (membership.IsMember) assignedRoles.Add(mapping.RoleName);
        }
        await SyncLdapRolesAsync(db, userId, assignedRoles, ct);
        // Com JIT ativo, quem não tem nenhum papel (nem por grupo, nem manual) não entra com uma sessão vazia.
        await using var roleCount = new MySqlCommand("SELECT COUNT(*) FROM UserRoles WHERE UserId=@id", connection);
        roleCount.Parameters.Add(P("@id", userId));
        if (Convert.ToInt32(await roleCount.ExecuteScalarAsync(ct)) == 0)
            return Results.Problem("Seu usuário foi autenticado no diretório, mas não pertence a nenhum grupo com acesso ao Atlas TI. Solicite acesso à equipe de TI.", statusCode: StatusCodes.Status403Forbidden);
    }
    var token = issuer.Create(canonicalSubject, typedLogin, displayName);
    return Results.Ok(new { accessToken = token.Token, tokenType = "Bearer", expiresAtUtc = token.ExpiresAtUtc });
}).RequireRateLimiting("ldap-login");

api.MapGet("/me", async (ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var externalId = user.FindFirstValue("oid") ?? user.FindFirstValue("sub");
    var permissions = await QueryAsync(db, "SELECT DISTINCT p.Code FROM Users u JOIN UserRoles ur ON ur.UserId=u.UserId JOIN RolePermissions rp ON rp.RoleId=ur.RoleId JOIN Permissions p ON p.PermissionId=rp.PermissionId WHERE u.ExternalId=@externalId AND u.IsActive=1 ORDER BY p.Code", [P("@externalId", externalId)], r => r.GetString(0), ct);
    var roles = await QueryAsync(db, "SELECT DISTINCT r.Name FROM Users u JOIN UserRoles ur ON ur.UserId=u.UserId JOIN Roles r ON r.RoleId=ur.RoleId WHERE u.ExternalId=@externalId AND u.IsActive=1 ORDER BY r.Name", [P("@externalId", externalId)], r => r.GetString(0), ct);
    return Results.Ok(new
    {
        subject = externalId,
        name = user.FindFirstValue("name"),
        login = user.FindFirstValue("preferred_username") ?? externalId,
        email = user.FindFirstValue("email"),
        permissions,
        roles
    });
}).RequireAuthorization();

api.MapGet("/me/profile", async (ClaimsPrincipal user, LdapAuthenticator ldap, IDataProtectionProvider protection, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var username = user.FindFirstValue("preferred_username") ?? user.FindFirstValue("sub");
    var settings = await ReadLdapSettingsAsync(db, ct);
    if (settings is null || string.IsNullOrWhiteSpace(settings.BindUser) || string.IsNullOrWhiteSpace(settings.BindPasswordProtected) || string.IsNullOrWhiteSpace(settings.BaseDn))
        return Results.Ok(new { available = false, attributes = new Dictionary<string, string?>() });
    string bindPassword;
    try { bindPassword = protection.CreateProtector("AtlasTi.Ldap.BindPassword.v1").Unprotect(settings.BindPasswordProtected); }
    catch (System.Security.Cryptography.CryptographicException) { return Results.Problem("Não foi possível descriptografar a credencial LDAP usada para consultar o perfil.", statusCode: StatusCodes.Status503ServiceUnavailable); }
    var result = ldap.ReadUserProfile(username!, bindPassword, settings);
    if (!result.Success) return Results.Problem("Não foi possível consultar os dados do usuário no Active Directory.", statusCode: StatusCodes.Status503ServiceUnavailable);
    var displayName = result.Attributes.GetValueOrDefault("displayName")
        ?? string.Join(' ', new[] { result.Attributes.GetValueOrDefault("givenName"), result.Attributes.GetValueOrDefault("sn") }.Where(x => !string.IsNullOrWhiteSpace(x)));
    if (!string.IsNullOrWhiteSpace(displayName))
    {
        await using var connection = await db.OpenAsync(ct);
        await using var sync = new MySqlCommand("UPDATE Users SET DisplayName=@name,Email=IF(@email IS NULL OR @email='' OR EXISTS(SELECT 1 FROM (SELECT UserId FROM Users WHERE Email=@email AND ExternalId<>@externalId) other),Email,@email) WHERE ExternalId=@externalId", connection);
        sync.Parameters.AddRange(new MySqlParameter[] { P("@name", displayName), P("@email", result.Attributes.GetValueOrDefault("mail")), P("@externalId", user.FindFirstValue("sub")) });
        await sync.ExecuteNonQueryAsync(ct);
    }
    return Results.Ok(new { available = true, attributes = result.Attributes });
}).RequireAuthorization();

api.MapGet("/categories", async (DatabaseConnectionFactory db, CancellationToken ct) =>
{
    const string sql = "SELECT CategoryId id, Name name, Slug slug, Description description FROM Categories WHERE IsActive=1 ORDER BY Name";
    return Results.Ok(await QueryAsync(db, sql, null, r => new { id = r.GetInt32(0), name = r.GetString(1), slug = r.GetString(2), description = NullableString(r, 3) }, ct));
}).RequireAuthorization(PermissionCodes.DocumentRead);

api.MapPost("/categories", async (CategoryUpdate request, ClaimsPrincipal actor, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var name = request.Name?.Trim();
    var slug = string.IsNullOrWhiteSpace(request.Slug) ? MakeSlug(name ?? "") : request.Slug.Trim();
    if (string.IsNullOrWhiteSpace(name) || name.Length > 120 || slug.Length > 140 || !System.Text.RegularExpressions.Regex.IsMatch(slug, "^[a-z0-9]+(?:-[a-z0-9]+)*$") || request.Description?.Length > 400)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["category"] = ["Informe nome válido (até 120 caracteres), slug válido e descrição de até 400 caracteres."] });
    await using var connection = await db.OpenAsync(ct);
    await using var command = new MySqlCommand("INSERT INTO Categories(Name,Slug,Description) VALUES(@name,@slug,@description)", connection);
    command.Parameters.AddRange(new MySqlParameter[] { P("@name", name), P("@slug", slug), P("@description", EmptyToNull(request.Description)) });
    long id;
    try { await command.ExecuteNonQueryAsync(ct); id = command.LastInsertedId; }
    catch (MySqlException ex) when (ex.Number == 1062) { return Results.Conflict(new { error = "Já existe uma categoria com esse nome ou identificador." }); }
    var actorId = await EnsureUserAsync(db, actor, ct);
    await AuditAsync(connection, actorId, id, "CategoryCreated", new { name, slug }, ct, entityType: "Category");
    return Results.Created($"/api/categories/{id}", new { id, name, slug, description = request.Description });
}).RequireAuthorization(PermissionCodes.CatalogManage);

api.MapPut("/categories/{id:int}", async (int id, CategoryUpdate request, ClaimsPrincipal actor, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var name = request.Name?.Trim();
    var slug = string.IsNullOrWhiteSpace(request.Slug) ? MakeSlug(name ?? "") : request.Slug.Trim();
    if (string.IsNullOrWhiteSpace(name) || name.Length > 120 || slug.Length > 140 || !System.Text.RegularExpressions.Regex.IsMatch(slug, "^[a-z0-9]+(?:-[a-z0-9]+)*$") || request.Description?.Length > 400)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["category"] = ["Informe nome válido (até 120 caracteres), slug válido e descrição de até 400 caracteres."] });
    await using var connection = await db.OpenAsync(ct);
    await using var command = new MySqlCommand("UPDATE Categories SET Name=@name,Slug=@slug,Description=COALESCE(@description,Description) WHERE CategoryId=@id AND IsActive=1", connection);
    command.Parameters.AddRange(new MySqlParameter[] { P("@name", name), P("@slug", slug), P("@description", EmptyToNull(request.Description)), P("@id", id) });
    try
    {
        if (await command.ExecuteNonQueryAsync(ct) == 0) return Results.NotFound();
    }
    catch (MySqlException ex) when (ex.Number == 1062) { return Results.Conflict(new { error = "Já existe uma categoria com esse nome ou identificador." }); }
    var actorId = await EnsureUserAsync(db, actor, ct);
    await AuditAsync(connection, actorId, id, "CategoryUpdated", new { name, slug }, ct, entityType: "Category");
    return Results.Ok(new { id, name, slug, request.Description });
}).RequireAuthorization(PermissionCodes.CatalogManage);

api.MapPost("/systems", async (SystemUpdate request, ClaimsPrincipal actor, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var name = request.Name?.Trim();
    if (string.IsNullOrWhiteSpace(name) || name.Length > 120 || request.OwnerTeam?.Length > 120 || request.Description?.Length > 400)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["system"] = ["Informe um nome de sistema com até 120 caracteres, equipe de até 120 e descrição de até 400."] });
    await using var connection = await db.OpenAsync(ct);
    await using var command = new MySqlCommand("INSERT INTO Systems(Name,OwnerTeam,Description) VALUES(@name,@team,@description)", connection);
    command.Parameters.AddRange(new MySqlParameter[] { P("@name", name), P("@team", EmptyToNull(request.OwnerTeam)), P("@description", EmptyToNull(request.Description)) });
    long id;
    try { await command.ExecuteNonQueryAsync(ct); id = command.LastInsertedId; }
    catch (MySqlException ex) when (ex.Number == 1062) { return Results.Conflict(new { error = "Já existe um sistema com esse nome." }); }
    var actorId = await EnsureUserAsync(db, actor, ct);
    await AuditAsync(connection, actorId, id, "SystemCreated", new { name }, ct, entityType: "System");
    return Results.Created($"/api/systems/{id}", new { id, name, ownerTeam = request.OwnerTeam, description = request.Description });
}).RequireAuthorization(PermissionCodes.CatalogManage);

api.MapPut("/systems/{id:int}", async (int id, SystemUpdate request, ClaimsPrincipal actor, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var name = request.Name?.Trim();
    if (string.IsNullOrWhiteSpace(name) || name.Length > 120 || request.OwnerTeam?.Length > 120 || request.Description?.Length > 400)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["system"] = ["Informe um nome de sistema com até 120 caracteres, equipe de até 120 e descrição de até 400."] });
    await using var connection = await db.OpenAsync(ct);
    await using var command = new MySqlCommand("UPDATE Systems SET Name=@name,OwnerTeam=@team,Description=@description WHERE SystemId=@id AND IsActive=1", connection);
    command.Parameters.AddRange(new MySqlParameter[] { P("@name", name), P("@team", EmptyToNull(request.OwnerTeam)), P("@description", EmptyToNull(request.Description)), P("@id", id) });
    try { if (await command.ExecuteNonQueryAsync(ct) == 0) return Results.NotFound(); }
    catch (MySqlException ex) when (ex.Number == 1062) { return Results.Conflict(new { error = "Já existe um sistema com esse nome." }); }
    var actorId = await EnsureUserAsync(db, actor, ct);
    await AuditAsync(connection, actorId, id, "SystemUpdated", new { name }, ct, entityType: "System");
    return Results.Ok(new { id, name, ownerTeam = request.OwnerTeam, description = request.Description });
}).RequireAuthorization(PermissionCodes.CatalogManage);

api.MapGet("/systems", async (DatabaseConnectionFactory db, CancellationToken ct) =>
{
    const string sql = "SELECT SystemId id, Name name, OwnerTeam ownerTeam, Description description FROM Systems WHERE IsActive=1 ORDER BY Name";
    return Results.Ok(await QueryAsync(db, sql, null, r => new { id = r.GetInt32(0), name = r.GetString(1), ownerTeam = NullableString(r, 2), description = NullableString(r, 3) }, ct));
}).RequireAuthorization(PermissionCodes.DocumentRead);

api.MapGet("/users/lookup", async (ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    if (!await HasAnyPermissionAsync(db, user, [PermissionCodes.DocumentManage, PermissionCodes.UserView, PermissionCodes.PermissionManage], ct)) return Results.Forbid();
    return Results.Ok(await QueryAsync(db, "SELECT UserId,ExternalId,DisplayName FROM Users WHERE IsActive=1 AND DeletedAt IS NULL ORDER BY DisplayName", null, r => new { id = r.GetInt64(0), externalId = r.GetString(1), name = r.GetString(2), isActive = true }, ct));
}).RequireAuthorization();

api.MapGet("/documents", async (string? q, int? categoryId, string? state, int? skip, int? take,
    ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var canSeeDrafts = await HasAnyPermissionAsync(db, user, [PermissionCodes.DocumentEdit, PermissionCodes.DocumentApprove], ct);
    var canManage = await HasAnyPermissionAsync(db, user, [PermissionCodes.PermissionManage, PermissionCodes.DocumentManage], ct);
    const string sql = """
        SELECT d.DocumentId, d.DocumentCode, d.Title, d.Summary, d.DocumentType, d.LifecycleState,
               c.Name, s.Name, v.VersionMajor, v.VersionMinor, v.CreatedAt, u.DisplayName, d.IsHidden
        FROM Documents d
        JOIN Categories c ON c.CategoryId=d.CategoryId
        LEFT JOIN Systems s ON s.SystemId=d.SystemId
        LEFT JOIN DocumentVersions v ON v.VersionId=d.CurrentVersionId
        JOIN Users u ON u.UserId=d.OwnerUserId
        WHERE d.DeletedAt IS NULL AND (d.IsHidden=0 OR @canManage=1) AND (@canManage=1 OR NOT EXISTS (SELECT 1 FROM UserRoles su JOIN DocumentScopeRules sr ON sr.RoleId=su.RoleId WHERE su.UserId=(SELECT UserId FROM Users WHERE ExternalId=@externalId)) OR EXISTS (SELECT 1 FROM UserRoles su JOIN DocumentScopeRules sr ON sr.RoleId=su.RoleId WHERE su.UserId=(SELECT UserId FROM Users WHERE ExternalId=@externalId) AND (sr.CategoryId IS NULL OR sr.CategoryId=d.CategoryId) AND (sr.DocumentType IS NULL OR sr.DocumentType=d.DocumentType))) AND (@canSeeDrafts=1 OR d.LifecycleState='Publicado' OR d.OwnerUserId=(SELECT UserId FROM Users WHERE ExternalId=@externalId))
          AND (@categoryId IS NULL OR d.CategoryId=@categoryId)
          AND (@state IS NULL OR d.LifecycleState=@state)
          AND (@q IS NULL OR d.Title LIKE CONCAT('%', @q, '%') OR d.Summary LIKE CONCAT('%', @q, '%') OR s.Name LIKE CONCAT('%', @q, '%'))
        ORDER BY d.UpdatedAt DESC LIMIT @take OFFSET @skip
        """;
    var p = new[] { P("@canSeeDrafts", canSeeDrafts), P("@canManage", canManage), P("@externalId", user.FindFirstValue("oid") ?? user.FindFirstValue("sub") ?? ""), P("@categoryId", categoryId), P("@state", NormalizeState(state)), P("@q", EmptyToNull(q)), P("@skip", Math.Max(0, skip ?? 0)), P("@take", Math.Clamp(take ?? 50, 1, 200)) };
    return Results.Ok(await QueryAsync(db, sql, p, DocumentSummary.Read, ct));
}).RequireAuthorization(PermissionCodes.DocumentRead);

api.MapGet("/documents/{id:long}", async (long id, ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    await using var connection = await db.OpenAsync(ct);
    var canSeeDrafts = await HasAnyPermissionAsync(db, user, [PermissionCodes.DocumentEdit, PermissionCodes.DocumentApprove], ct);
    var canManage = await HasAnyPermissionAsync(db, user, [PermissionCodes.PermissionManage, PermissionCodes.DocumentManage], ct);
    const string sql = """
        SELECT d.DocumentId, d.DocumentCode, d.Title, d.Summary, d.DocumentType, d.LifecycleState, c.CategoryId, c.Name,
               s.SystemId, s.Name, d.OwnerUserId, u.DisplayName, d.UpdatedAt, v.VersionId, v.VersionMajor, v.VersionMinor,
               v.ChangeSummary, v.Content, v.CreatedAt, v.OriginalFileName, v.ContentType, v.FileSizeBytes
        FROM Documents d JOIN Categories c ON c.CategoryId=d.CategoryId
        LEFT JOIN Systems s ON s.SystemId=d.SystemId JOIN Users u ON u.UserId=d.OwnerUserId
        LEFT JOIN DocumentVersions v ON v.VersionId=d.CurrentVersionId
        WHERE d.DocumentId=@id AND d.DeletedAt IS NULL AND (d.IsHidden=0 OR @canManage=1) AND (@canManage=1 OR NOT EXISTS (SELECT 1 FROM UserRoles su JOIN DocumentScopeRules sr ON sr.RoleId=su.RoleId WHERE su.UserId=(SELECT UserId FROM Users WHERE ExternalId=@externalId)) OR EXISTS (SELECT 1 FROM UserRoles su JOIN DocumentScopeRules sr ON sr.RoleId=su.RoleId WHERE su.UserId=(SELECT UserId FROM Users WHERE ExternalId=@externalId) AND (sr.CategoryId IS NULL OR sr.CategoryId=d.CategoryId) AND (sr.DocumentType IS NULL OR sr.DocumentType=d.DocumentType))) AND (@canSeeDrafts=1 OR d.LifecycleState='Publicado')
        """;
    await using var command = new MySqlCommand(sql, connection);
    command.Parameters.AddRange(new MySqlParameter[] {P("@id", id), P("@canSeeDrafts", canSeeDrafts), P("@canManage", canManage), P("@externalId", user.FindFirstValue("oid") ?? user.FindFirstValue("sub") ?? "")});
    await using var reader = await command.ExecuteReaderAsync(ct);
    if (!await reader.ReadAsync(ct)) return Results.NotFound();
    var document = DocumentDetail.Read(reader);
    await reader.DisposeAsync();
    var versions = await QueryConnectionAsync(connection,
        "SELECT VersionId, VersionMajor, VersionMinor, ChangeSummary, CreatedAt, IsPublished, OriginalFileName, ContentType, FileSizeBytes FROM DocumentVersions WHERE DocumentId=@id ORDER BY VersionMajor DESC, VersionMinor DESC",
        [P("@id", id)], r => new DocumentVersionDto(r.GetInt64(0), $"v{r.GetInt32(1)}.{r.GetInt32(2)}", r.GetString(3), r.GetDateTime(4), r.GetBoolean(5), NullableString(r, 6), NullableString(r, 7), r.IsDBNull(8) ? null : r.GetInt64(8)), ct);
    var tags = await QueryConnectionAsync(connection, "SELECT Tag FROM DocumentTags WHERE DocumentId=@id ORDER BY Tag", [P("@id", id)], r => r.GetString(0), ct);
    var ownerLogin = (await QueryConnectionAsync(connection, "SELECT u.ExternalId FROM Documents d JOIN Users u ON u.UserId=d.OwnerUserId WHERE d.DocumentId=@id", [P("@id", id)], r => r.GetString(0), ct)).FirstOrDefault();
    var submitter = (await QueryConnectionAsync(connection, "SELECT u.DisplayName,u.ExternalId FROM Approvals a JOIN DocumentVersions v ON v.VersionId=a.VersionId JOIN Users u ON u.UserId=a.RequestedByUserId WHERE v.DocumentId=@id ORDER BY a.RequestedAt DESC,a.ApprovalId DESC LIMIT 1", [P("@id", id)], r => (Name: r.GetString(0), Login: r.GetString(1)), ct)).FirstOrDefault();
    // Logins só aparecem para quem administra; o nome do autor/remetente é público como já era o do autor.
    return Results.Ok(document with { Versions = versions, Tags = tags, OwnerExternalId = canManage ? ownerLogin : null, SubmittedBy = submitter.Name, SubmittedByExternalId = canManage ? submitter.Login : null });
}).RequireAuthorization(PermissionCodes.DocumentRead);

api.MapPost("/documents", async (DocumentCreate request, ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var validation = ValidateDocument(request.Title, request.DocumentType);
    if (validation is not null) return Results.ValidationProblem(validation);
    var actor = await EnsureUserAsync(db, user, ct);
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    const string insert = """
        INSERT INTO Documents(Title,Summary,DocumentType,CategoryId,SystemId,LifecycleState,OwnerUserId)
        VALUES(@title,@summary,@type,@categoryId,@systemId,'Revisao',@actor)
        """;
    long id;
    await using (var cmd = new MySqlCommand(insert, connection, tx))
    {
        cmd.Parameters.AddRange(new MySqlParameter[] {P("@title", request.Title.Trim()), P("@summary", EmptyToNull(request.Summary)), P("@type", NormalizeType(request.DocumentType)), P("@categoryId", request.CategoryId), P("@systemId", request.SystemId), P("@actor", actor)});
        await cmd.ExecuteNonQueryAsync(ct);
        id = cmd.LastInsertedId;
    }
    long versionId;
    await using (var cmd = new MySqlCommand("INSERT INTO DocumentVersions(DocumentId,VersionMajor,VersionMinor,ChangeSummary,Content,CreatedByUserId) VALUES(@id,1,0,@summary,@content,@actor)", connection, tx))
    {
        cmd.Parameters.AddRange(new MySqlParameter[] {P("@id", id), P("@summary", "Criação inicial"), P("@content", request.Content), P("@actor", actor)});
        await cmd.ExecuteNonQueryAsync(ct);
        versionId = cmd.LastInsertedId;
    }
    await using (var code = new MySqlCommand("UPDATE Documents SET DocumentCode=CONCAT('DOC-',LPAD(DocumentId,8,'0')) WHERE DocumentId=@id", connection, tx))
    {
        code.Parameters.Add(P("@id", id));
        await code.ExecuteNonQueryAsync(ct);
    }
    await using (var cmd = new MySqlCommand("UPDATE Documents SET CurrentVersionId=@version,UpdatedAt=UTC_TIMESTAMP(3) WHERE DocumentId=@id", connection, tx))
    {
        cmd.Parameters.AddRange(new MySqlParameter[] {P("@version", versionId), P("@id", id)});
        await cmd.ExecuteNonQueryAsync(ct);
    }
    await AuditAsync(connection, actor, id, "Created", new { version = "v1.0", state = "Revisao" }, ct, tx);
    await InsertTagsAsync(connection, tx, id, request.Tags, ct);
    await tx.CommitAsync(ct);
    return Results.Created($"/api/documents/{id}", new { id, versionId, state = "Revisao", version = "v1.0" });
}).RequireAuthorization(PermissionCodes.DocumentCreate);

api.MapPost("/documents/upload", async (HttpRequest http, ClaimsPrincipal user, DatabaseConnectionFactory db, DocumentFileStore fileStore, CancellationToken ct) =>
{
    var form = await http.ReadFormAsync(ct);
    var title = form["title"].ToString().Trim();
    var type = form["documentType"].ToString();
    if (!int.TryParse(form["categoryId"], out var categoryId)) return Results.ValidationProblem(new Dictionary<string, string[]> { ["categoryId"] = ["Selecione uma categoria válida."] });
    int? systemId = int.TryParse(form["systemId"], out var parsedSystemId) ? parsedSystemId : null;
    var validation = ValidateDocument(title, type);
    if (validation is not null) return Results.ValidationProblem(validation);
    var file = form.Files.GetFile("file");
    var content = form["content"].ToString();
    if (file is null && string.IsNullOrWhiteSpace(content)) return Results.ValidationProblem(new Dictionary<string, string[]> { ["content"] = ["Informe o conteúdo ou anexe um arquivo."] });

    StoredDocumentFile? stored = null;
    if (file is not null)
    {
        try { stored = await fileStore.SaveAsync(file, ct); }
        catch (InvalidDataException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["file"] = [ex.Message] }); }
    }
    var committed = false;
    try
    {
        var actor = await EnsureUserAsync(db, user, ct);
        await using var connection = await db.OpenAsync(ct);
        await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
        long id;
        await using (var insertDocument = new MySqlCommand("INSERT INTO Documents(Title,Summary,DocumentType,CategoryId,SystemId,LifecycleState,OwnerUserId) VALUES(@title,@summary,@type,@categoryId,@systemId,'Revisao',@actor)", connection, tx))
        {
            insertDocument.Parameters.AddRange(new MySqlParameter[] { P("@title", title), P("@summary", EmptyToNull(form["summary"])), P("@type", NormalizeType(type)), P("@categoryId", categoryId), P("@systemId", systemId), P("@actor", actor) });
            await insertDocument.ExecuteNonQueryAsync(ct);
            id = insertDocument.LastInsertedId;
        }
        long versionId;
        await using (var insertVersion = new MySqlCommand("INSERT INTO DocumentVersions(DocumentId,VersionMajor,VersionMinor,ChangeSummary,Content,StorageUri,ContentHash,OriginalFileName,ContentType,FileSizeBytes,CreatedByUserId) VALUES(@id,1,0,'Criação inicial',@content,@uri,@hash,@fileName,@contentType,@size,@actor)", connection, tx))
        {
            insertVersion.Parameters.AddRange(new MySqlParameter[] { P("@id", id), P("@content", EmptyToNull(content)), P("@uri", stored?.StorageUri), P("@hash", stored?.Sha256), P("@fileName", stored?.OriginalFileName), P("@contentType", stored?.ContentType), P("@size", stored?.Size), P("@actor", actor) });
            await insertVersion.ExecuteNonQueryAsync(ct);
            versionId = insertVersion.LastInsertedId;
        }
        await using (var update = new MySqlCommand("UPDATE Documents SET DocumentCode=CONCAT('DOC-',LPAD(DocumentId,8,'0')),CurrentVersionId=@version,UpdatedAt=UTC_TIMESTAMP(3) WHERE DocumentId=@id", connection, tx))
        {
            update.Parameters.AddRange(new MySqlParameter[] { P("@version", versionId), P("@id", id) });
            await update.ExecuteNonQueryAsync(ct);
        }
        await AuditAsync(connection, actor, id, "Created", new { version = "v1.0", state = "Revisao", fileName = stored?.OriginalFileName }, ct, tx);
        await InsertTagsAsync(connection, tx, id, ParseFormTags(form["tags"]), ct);
        await tx.CommitAsync(ct);
        committed = true;
        return Results.Created($"/api/documents/{id}", new { id, versionId, state = "Revisao", version = "v1.0" });
    }
    finally
    {
        if (!committed && stored is not null) fileStore.Delete(stored.StorageUri);
    }
}).DisableAntiforgery().RequireAuthorization(PermissionCodes.DocumentCreate);

api.MapPut("/documents/{id:long}", async (long id, DocumentUpdate request, ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var validation = ValidateDocument(request.Title, request.DocumentType);
    if (validation is not null) return Results.ValidationProblem(validation);
    await using var connection = await db.OpenAsync(ct);
    var actor = await EnsureUserAsync(db, user, ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    await using var cmd = new MySqlCommand("UPDATE Documents SET Title=@title,Summary=@summary,DocumentType=@type,CategoryId=@categoryId,SystemId=@systemId,UpdatedAt=UTC_TIMESTAMP(3) WHERE DocumentId=@id AND DeletedAt IS NULL", connection, tx);
    cmd.Parameters.AddRange(new MySqlParameter[] {P("@title", request.Title.Trim()), P("@summary", EmptyToNull(request.Summary)), P("@type", NormalizeType(request.DocumentType)), P("@categoryId", request.CategoryId), P("@systemId", request.SystemId), P("@id", id)});
    if (await cmd.ExecuteNonQueryAsync(ct) == 0) return Results.NotFound();
    await using (var audit = new MySqlCommand("INSERT INTO AuditLog(ActorUserId,EntityType,EntityId,Action) VALUES(@actor,'Document',@id,'Updated')", connection, tx))
    {
        audit.Parameters.AddRange(new MySqlParameter[] {P("@actor", actor), P("@id", id)});
        await audit.ExecuteNonQueryAsync(ct);
    }
    await using (var clear = new MySqlCommand("DELETE FROM DocumentTags WHERE DocumentId=@id", connection, tx))
    {
        clear.Parameters.Add(P("@id", id));
        await clear.ExecuteNonQueryAsync(ct);
    }
    await InsertTagsAsync(connection, tx, id, request.Tags, ct);
    await tx.CommitAsync(ct);
    return Results.NoContent();
}).RequireAuthorization(PermissionCodes.DocumentEdit);

api.MapPost("/documents/{id:long}/versions/upload", async (long id, HttpRequest http, ClaimsPrincipal user, DatabaseConnectionFactory db, DocumentFileStore fileStore, CancellationToken ct) =>
{
    var form = await http.ReadFormAsync(ct);
    var summary = form["changeSummary"].ToString().Trim();
    if (string.IsNullOrWhiteSpace(summary)) return Results.ValidationProblem(new Dictionary<string, string[]> { ["changeSummary"] = ["Informe o resumo das alterações."] });
    var versionType = string.IsNullOrWhiteSpace(form["versionType"]) ? "minor" : form["versionType"].ToString().Trim().ToLowerInvariant();
    if (versionType is not ("minor" or "major")) return Results.ValidationProblem(new Dictionary<string, string[]> { ["versionType"] = ["Use minor para correções ou major para reformulações."] });
    var content = form["content"].ToString();
    var file = form.Files.GetFile("file");
    if (file is null && string.IsNullOrWhiteSpace(content)) return Results.ValidationProblem(new Dictionary<string, string[]> { ["content"] = ["Informe o conteúdo ou anexe um arquivo."] });
    StoredDocumentFile? stored = null;
    if (file is not null)
    {
        try { stored = await fileStore.SaveAsync(file, ct); }
        catch (InvalidDataException ex) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["file"] = [ex.Message] }); }
    }
    var committed = false;
    try
    {
        var actor = await EnsureUserAsync(db, user, ct);
        await using var connection = await db.OpenAsync(ct);
        await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
        await using var current = new MySqlCommand("SELECT VersionMajor,VersionMinor,Content,StorageUri,ContentHash,OriginalFileName,ContentType,FileSizeBytes FROM DocumentVersions WHERE DocumentId=@id ORDER BY VersionMajor DESC,VersionMinor DESC LIMIT 1 FOR UPDATE", connection, tx);
        current.Parameters.Add(P("@id", id));
        await using var reader = await current.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return Results.NotFound();
        var currentMajor = reader.GetInt32(0); var currentMinor = reader.GetInt32(1);
        var major = currentMajor + (versionType == "major" ? 1 : 0);
        var minor = versionType == "major" ? 0 : currentMinor + 1;
        var currentContent = NullableString(reader, 2);
        var currentStorageUri = NullableString(reader, 3);
        var currentContentHash = reader.IsDBNull(4) ? null : (byte[])reader[4];
        var currentFileName = NullableString(reader, 5);
        var currentContentType = NullableString(reader, 6);
        long? currentFileSize = reader.IsDBNull(7) ? null : reader.GetInt64(7);
        await reader.DisposeAsync();
        await using (var cancel = new MySqlCommand("UPDATE Approvals a JOIN DocumentVersions v ON v.VersionId=a.VersionId SET a.Decision='Cancelado',a.DecidedAt=UTC_TIMESTAMP(3),a.Comment='Cancelado pela criação de uma nova versão.' WHERE v.DocumentId=@id AND a.Decision='Pendente'", connection, tx))
        {
            cancel.Parameters.Add(P("@id", id));
            await cancel.ExecuteNonQueryAsync(ct);
        }
        long versionId;
        await using (var insert = new MySqlCommand("INSERT INTO DocumentVersions(DocumentId,VersionMajor,VersionMinor,ChangeSummary,Content,StorageUri,ContentHash,OriginalFileName,ContentType,FileSizeBytes,CreatedByUserId) VALUES(@id,@major,@minor,@summary,@content,@uri,@hash,@fileName,@contentType,@size,@actor)", connection, tx))
        {
            insert.Parameters.AddRange(new MySqlParameter[] { P("@id", id), P("@major", major), P("@minor", minor), P("@summary", summary), P("@content", EmptyToNull(content) ?? currentContent), P("@uri", stored?.StorageUri ?? currentStorageUri), P("@hash", stored?.Sha256 ?? currentContentHash), P("@fileName", stored?.OriginalFileName ?? currentFileName), P("@contentType", stored?.ContentType ?? currentContentType), P("@size", stored?.Size ?? currentFileSize), P("@actor", actor) });
            await insert.ExecuteNonQueryAsync(ct);
            versionId = insert.LastInsertedId;
        }
        await using (var update = new MySqlCommand("UPDATE Documents SET CurrentVersionId=@version,LifecycleState='Revisao',UpdatedAt=UTC_TIMESTAMP(3) WHERE DocumentId=@id AND DeletedAt IS NULL", connection, tx))
        {
            update.Parameters.AddRange(new MySqlParameter[] { P("@version", versionId), P("@id", id) });
            if (await update.ExecuteNonQueryAsync(ct) == 0) return Results.NotFound();
        }
        await AuditAsync(connection, actor, id, "VersionCreated", new { version = $"v{major}.{minor}", summary, fileName = stored?.OriginalFileName }, ct, tx);
        await tx.CommitAsync(ct);
        committed = true;
        return Results.Created($"/api/documents/{id}/versions/{versionId}", new { id, versionId, version = $"v{major}.{minor}", state = "Revisao" });
    }
    finally
    {
        if (!committed && stored is not null) fileStore.Delete(stored.StorageUri);
    }
}).DisableAntiforgery().RequireAuthorization(PermissionCodes.DocumentEdit);

api.MapGet("/documents/{id:long}/versions/{versionId:long}/file", async (long id, long versionId, bool? download, ClaimsPrincipal user, DatabaseConnectionFactory db, DocumentFileStore fileStore, CancellationToken ct) =>
{
    var canSeeDrafts = await HasAnyPermissionAsync(db, user, [PermissionCodes.DocumentEdit, PermissionCodes.DocumentApprove], ct);
    var canManage = await HasAnyPermissionAsync(db, user, [PermissionCodes.PermissionManage, PermissionCodes.DocumentManage], ct);
    await using var connection = await db.OpenAsync(ct);
    await using var command = new MySqlCommand("SELECT v.StorageUri,v.OriginalFileName,v.ContentType,d.LifecycleState FROM DocumentVersions v JOIN Documents d ON d.DocumentId=v.DocumentId WHERE v.VersionId=@version AND v.DocumentId=@id AND d.DeletedAt IS NULL AND (d.IsHidden=0 OR @canManage=1) AND (@canManage=1 OR NOT EXISTS (SELECT 1 FROM UserRoles su JOIN DocumentScopeRules sr ON sr.RoleId=su.RoleId WHERE su.UserId=(SELECT UserId FROM Users WHERE ExternalId=@externalId)) OR EXISTS (SELECT 1 FROM UserRoles su JOIN DocumentScopeRules sr ON sr.RoleId=su.RoleId WHERE su.UserId=(SELECT UserId FROM Users WHERE ExternalId=@externalId) AND (sr.CategoryId IS NULL OR sr.CategoryId=d.CategoryId) AND (sr.DocumentType IS NULL OR sr.DocumentType=d.DocumentType))) AND (@canSeeDrafts=1 OR d.LifecycleState='Publicado')", connection);
    command.Parameters.AddRange(new MySqlParameter[] { P("@version", versionId), P("@id", id), P("@canSeeDrafts", canSeeDrafts), P("@canManage", canManage), P("@externalId", user.FindFirstValue("oid") ?? user.FindFirstValue("sub") ?? "") });
    await using var reader = await command.ExecuteReaderAsync(ct);
    if (!await reader.ReadAsync(ct) || reader.IsDBNull(0)) return Results.NotFound();
    var storageUri = reader.GetString(0); var fileName = reader.GetString(1); var contentType = reader.GetString(2);
    await reader.DisposeAsync();
    var path = fileStore.Resolve(storageUri);
    if (!File.Exists(path)) return Results.NotFound();
    var isPdf = contentType == "application/pdf";
    return Results.File(path, contentType, fileDownloadName: download == true || !isPdf ? fileName : null, enableRangeProcessing: true);
}).RequireAuthorization(PermissionCodes.DocumentRead);

api.MapGet("/documents/{id:long}/versions/{versionId:long}", async (long id, long versionId, ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var canSeeDrafts = await HasAnyPermissionAsync(db, user, [PermissionCodes.DocumentEdit, PermissionCodes.DocumentApprove], ct);
    var canManage = await HasAnyPermissionAsync(db, user, [PermissionCodes.PermissionManage, PermissionCodes.DocumentManage], ct);
    await using var connection = await db.OpenAsync(ct);
    await using var command = new MySqlCommand("SELECT v.VersionMajor,v.VersionMinor,v.ChangeSummary,v.Content,v.CreatedAt,v.IsPublished,v.OriginalFileName,v.ContentType,v.FileSizeBytes,(v.StorageUri IS NOT NULL),d.LifecycleState FROM DocumentVersions v JOIN Documents d ON d.DocumentId=v.DocumentId WHERE v.VersionId=@version AND v.DocumentId=@id AND d.DeletedAt IS NULL AND (d.IsHidden=0 OR @canManage=1) AND (@canManage=1 OR NOT EXISTS (SELECT 1 FROM UserRoles su JOIN DocumentScopeRules sr ON sr.RoleId=su.RoleId WHERE su.UserId=(SELECT UserId FROM Users WHERE ExternalId=@externalId)) OR EXISTS (SELECT 1 FROM UserRoles su JOIN DocumentScopeRules sr ON sr.RoleId=su.RoleId WHERE su.UserId=(SELECT UserId FROM Users WHERE ExternalId=@externalId) AND (sr.CategoryId IS NULL OR sr.CategoryId=d.CategoryId) AND (sr.DocumentType IS NULL OR sr.DocumentType=d.DocumentType))) AND (@canSeeDrafts=1 OR d.LifecycleState='Publicado')", connection);
    command.Parameters.AddRange(new MySqlParameter[] { P("@version", versionId), P("@id", id), P("@canSeeDrafts", canSeeDrafts), P("@canManage", canManage) });
    await using var reader = await command.ExecuteReaderAsync(ct);
    if (!await reader.ReadAsync(ct)) return Results.NotFound();
    var hasFile = reader.GetBoolean(9);
    return Results.Ok(new
    {
        versionId,
        version = $"v{reader.GetInt32(0)}.{reader.GetInt32(1)}",
        changeSummary = reader.GetString(2),
        content = NullableString(reader, 3),
        createdAt = reader.GetDateTime(4),
        isPublished = reader.GetBoolean(5),
        originalFileName = NullableString(reader, 6),
        contentType = NullableString(reader, 7),
        fileSizeBytes = reader.IsDBNull(8) ? (long?)null : reader.GetInt64(8),
        fileUrl = hasFile ? $"/api/documents/{id}/versions/{versionId}/file" : null
    });
}).RequireAuthorization(PermissionCodes.DocumentRead);

api.MapPost("/documents/{id:long}/versions", async (long id, VersionCreate request, ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(request.ChangeSummary)) return Results.ValidationProblem(new Dictionary<string, string[]> { ["changeSummary"] = ["Informe o resumo das alterações."] });
    var versionType = string.IsNullOrWhiteSpace(request.VersionType) ? "minor" : request.VersionType.Trim().ToLowerInvariant();
    if (versionType is not ("minor" or "major")) return Results.ValidationProblem(new Dictionary<string, string[]> { ["versionType"] = ["Use minor para correções ou major para reformulações."] });
    var actor = await EnsureUserAsync(db, user, ct);
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    await using var current = new MySqlCommand("SELECT VersionMajor,VersionMinor FROM DocumentVersions WHERE DocumentId=@id ORDER BY VersionMajor DESC,VersionMinor DESC LIMIT 1", connection, tx);
    current.Parameters.Add(P("@id", id));
    await using var reader = await current.ExecuteReaderAsync(ct);
    if (!await reader.ReadAsync(ct)) return Results.NotFound();
    var currentMajor = reader.GetInt32(0); var currentMinor = reader.GetInt32(1);
    var major = currentMajor + (versionType == "major" ? 1 : 0);
    var minor = versionType == "major" ? 0 : currentMinor + 1;
    await reader.DisposeAsync();
    await using (var cancel = new MySqlCommand("UPDATE Approvals a JOIN DocumentVersions v ON v.VersionId=a.VersionId SET a.Decision='Cancelado',a.DecidedAt=UTC_TIMESTAMP(3),a.Comment='Cancelado pela criação de uma nova versão.' WHERE v.DocumentId=@id AND a.Decision='Pendente'", connection, tx))
    {
        cancel.Parameters.Add(P("@id", id));
        await cancel.ExecuteNonQueryAsync(ct);
    }
    await using var insert = new MySqlCommand("INSERT INTO DocumentVersions(DocumentId,VersionMajor,VersionMinor,ChangeSummary,Content,CreatedByUserId) VALUES(@id,@major,@minor,@summary,@content,@actor)", connection, tx);
    insert.Parameters.AddRange(new MySqlParameter[] {P("@id", id), P("@major", major), P("@minor", minor), P("@summary", request.ChangeSummary.Trim()), P("@content", request.Content), P("@actor", actor)});
    await insert.ExecuteNonQueryAsync(ct);
    var versionId = insert.LastInsertedId;
    await using (var update = new MySqlCommand("UPDATE Documents SET CurrentVersionId=@version,LifecycleState='Revisao',UpdatedAt=UTC_TIMESTAMP(3) WHERE DocumentId=@id", connection, tx))
    {
        update.Parameters.AddRange(new MySqlParameter[] {P("@version", versionId), P("@id", id), P("@actor", actor), P("@details", JsonSerializer.Serialize(new { version = $"v{major}.{minor}", request.ChangeSummary }))});
        await update.ExecuteNonQueryAsync(ct);
    }
    await AuditAsync(connection, actor, id, "VersionCreated", new { version = $"v{major}.{minor}", request.ChangeSummary }, ct, tx);
    await tx.CommitAsync(ct);
    return Results.Created($"/api/documents/{id}", new { id, versionId, version = $"v{major}.{minor}", state = "Revisao" });
}).RequireAuthorization(PermissionCodes.DocumentEdit);

api.MapPost("/documents/{id:long}/submit", async (long id, ApprovalRequest request, ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var actor = await EnsureUserAsync(db, user, ct);
    await using var connection = await db.OpenAsync(ct);
    await using var cmd = new MySqlCommand("""
        INSERT INTO Approvals(VersionId,RequestedByUserId,Comment)
        SELECT d.CurrentVersionId,@actor,@comment FROM Documents d WHERE d.DocumentId=@id AND d.DeletedAt IS NULL AND d.LifecycleState='Revisao'
        AND d.CurrentVersionId IS NOT NULL AND NOT EXISTS(SELECT 1 FROM Approvals a WHERE a.VersionId=d.CurrentVersionId AND a.Decision='Pendente')
        """, connection);
    cmd.Parameters.AddRange(new MySqlParameter[] {P("@actor", actor), P("@comment", EmptyToNull(request.Comment)), P("@id", id)});
    if (await cmd.ExecuteNonQueryAsync(ct) == 0) return Results.Conflict(new { error = "Documento inexistente, fora de revisão ou já submetido." });
    var approvalId = cmd.LastInsertedId;
    await AuditAsync(connection, actor, id, "ApprovalRequested", new { approvalId }, ct);
    return Results.Created($"/api/approvals/{approvalId}", new { approvalId, state = "Pendente" });
}).RequireAuthorization(PermissionCodes.DocumentSubmit);

api.MapPost("/approvals/{approvalId:long}/decision", async (long approvalId, ApprovalDecision request, ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    if (request.Decision is not ("Aprovado" or "Rejeitado")) return Results.ValidationProblem(new Dictionary<string, string[]> { ["decision"] = ["A decisão deve ser Aprovado ou Rejeitado."] });
    var actor = await EnsureUserAsync(db, user, ct);
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    await using (var requester = new MySqlCommand("SELECT RequestedByUserId FROM Approvals WHERE ApprovalId=@id AND Decision='Pendente'", connection, tx))
    {
        requester.Parameters.Add(P("@id", approvalId));
        var requesterId = await requester.ExecuteScalarAsync(ct);
        if (requesterId is null) return Results.NotFound();
        if (Convert.ToInt64(requesterId) == actor) return Results.Conflict(new { error = "Quem enviou esta versão para aprovação não pode aprová-la." });
    }
    await using var cmd = new MySqlCommand("UPDATE Approvals SET Decision=@decision,ApproverUserId=@actor,DecidedAt=UTC_TIMESTAMP(3),Comment=@comment WHERE ApprovalId=@id AND Decision='Pendente'", connection, tx);
    cmd.Parameters.AddRange(new MySqlParameter[] {P("@decision", request.Decision), P("@actor", actor), P("@comment", EmptyToNull(request.Comment)), P("@id", approvalId)});
    if (await cmd.ExecuteNonQueryAsync(ct) == 0) return Results.NotFound();
    long versionId;
    await using (var readVersion = new MySqlCommand("SELECT VersionId FROM Approvals WHERE ApprovalId=@id", connection, tx))
    {
        readVersion.Parameters.Add(P("@id", approvalId));
        versionId = Convert.ToInt64(await readVersion.ExecuteScalarAsync(ct));
    }
    await using (var update = new MySqlCommand("UPDATE Documents d JOIN DocumentVersions v ON v.DocumentId=d.DocumentId SET d.LifecycleState=@state,d.UpdatedAt=UTC_TIMESTAMP(3) WHERE v.VersionId=@version", connection, tx))
    {
        update.Parameters.AddRange(new MySqlParameter[] {P("@state", request.Decision == "Aprovado" ? "Publicado" : "Revisao"), P("@version", versionId)});
        await update.ExecuteNonQueryAsync(ct);
        await using var publishVersion = new MySqlCommand("UPDATE DocumentVersions SET IsPublished=CASE WHEN @approved=1 THEN TRUE ELSE IsPublished END WHERE VersionId=@version", connection, tx);
        publishVersion.Parameters.AddRange(new MySqlParameter[] {P("@approved", request.Decision == "Aprovado"), P("@version", versionId)});
        await publishVersion.ExecuteNonQueryAsync(ct);
        await using var getDocument = new MySqlCommand("SELECT DocumentId FROM DocumentVersions WHERE VersionId=@version", connection, tx);
        getDocument.Parameters.Add(P("@version", versionId));
        var documentId = Convert.ToInt64(await getDocument.ExecuteScalarAsync(ct));
        await using var audit = new MySqlCommand("INSERT INTO AuditLog(ActorUserId,EntityType,EntityId,Action,DetailsJson) VALUES(@actor,'Document',@id,'ApprovalDecision',@details)", connection, tx);
        audit.Parameters.AddRange(new MySqlParameter[] {P("@actor", actor), P("@id", documentId), P("@details", JsonSerializer.Serialize(new { approvalId, request.Decision, request.Comment }))});
        await audit.ExecuteNonQueryAsync(ct);
    }
    await tx.CommitAsync(ct);
    return Results.Ok(new { approvalId, state = request.Decision });
}).RequireAuthorization(PermissionCodes.DocumentApprove);

api.MapPatch("/documents/{id:long}/state", async (long id, StateChange request, ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    if (request.State is not ("Obsoleto" or "Inativo" or "Revisao")) return Results.ValidationProblem(new Dictionary<string, string[]> { ["state"] = ["Use Obsoleto, Inativo ou Revisao. Publicação exige aprovação."] });
    var actor = await EnsureUserAsync(db, user, ct);
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    await using var cmd = new MySqlCommand("UPDATE Documents SET LifecycleState=@state,UpdatedAt=UTC_TIMESTAMP(3) WHERE DocumentId=@id AND DeletedAt IS NULL", connection, tx);
    cmd.Parameters.AddRange(new MySqlParameter[] {P("@state", request.State), P("@id", id)});
    if (await cmd.ExecuteNonQueryAsync(ct) == 0) return Results.NotFound();
    await using var audit = new MySqlCommand("INSERT INTO AuditLog(ActorUserId,EntityType,EntityId,Action,DetailsJson) VALUES(@actor,'Document',@id,'StateChanged',@details)", connection, tx);
    audit.Parameters.AddRange(new MySqlParameter[] {P("@actor", actor), P("@id", id), P("@details", JsonSerializer.Serialize(new { request.State, request.Reason }))});
    await audit.ExecuteNonQueryAsync(ct);
    await tx.CommitAsync(ct);
    return Results.NoContent();
}).RequireAuthorization(PermissionCodes.DocumentChangeState);

api.MapGet("/approvals/pending", async (DatabaseConnectionFactory db, CancellationToken ct) =>
{
    const string sql = """
        SELECT a.ApprovalId,d.DocumentId,d.DocumentCode,d.Title,v.VersionMajor,v.VersionMinor,a.RequestedAt,a.Comment,u.DisplayName
        FROM Approvals a JOIN DocumentVersions v ON v.VersionId=a.VersionId JOIN Documents d ON d.DocumentId=v.DocumentId
        JOIN Users u ON u.UserId=a.RequestedByUserId WHERE a.Decision='Pendente' ORDER BY a.RequestedAt
        """;
    return Results.Ok(await QueryAsync(db, sql, null, r => new { approvalId = r.GetInt64(0), documentId = r.GetInt64(1), code = r.GetString(2), title = r.GetString(3), version = $"v{r.GetInt32(4)}.{r.GetInt32(5)}", requestedAt = r.GetDateTime(6), comment = NullableString(r, 7), requestedBy = r.GetString(8) }, ct));
}).RequireAuthorization(PermissionCodes.DocumentApprove);

var admin = api.MapGroup("/admin").RequireAuthorization();
admin.MapPatch("/documents/{id:long}/attribution", async (long id, DocumentAttributionUpdate request, ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(request.OwnerExternalId)) return Results.ValidationProblem(new Dictionary<string, string[]> { ["ownerExternalId"] = ["Informe o responsável do documento."] });
    var actor = await EnsureUserAsync(db, user, ct);
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    async Task<long?> FindUser(string? externalId)
    {
        if (string.IsNullOrWhiteSpace(externalId)) return null;
        await using var lookup = new MySqlCommand("SELECT UserId FROM Users WHERE ExternalId=@externalId AND IsActive=1", connection, tx);
        lookup.Parameters.Add(P("@externalId", externalId.Trim()));
        var value = await lookup.ExecuteScalarAsync(ct);
        return value is null ? null : Convert.ToInt64(value);
    }
    var ownerId = await FindUser(request.OwnerExternalId);
    if (ownerId is null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["ownerExternalId"] = ["O responsável precisa ser um usuário ativo conhecido pelo Atlas TI."] });
    long? requestedById = null;
    if (!string.IsNullOrWhiteSpace(request.RequestedByExternalId))
    {
        requestedById = await FindUser(request.RequestedByExternalId);
        if (requestedById is null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["requestedByExternalId"] = ["Quem enviou para revisão precisa ser um usuário ativo conhecido pelo Atlas TI."] });
    }
    await using (var updateOwner = new MySqlCommand("UPDATE Documents SET OwnerUserId=@owner,UpdatedAt=UTC_TIMESTAMP(3) WHERE DocumentId=@id AND DeletedAt IS NULL", connection, tx))
    {
        updateOwner.Parameters.AddRange(new MySqlParameter[] { P("@owner", ownerId.Value), P("@id", id) });
        if (await updateOwner.ExecuteNonQueryAsync(ct) == 0) return Results.NotFound();
    }
    if (requestedById.HasValue)
    {
        await using var updateRequester = new MySqlCommand("UPDATE Approvals SET RequestedByUserId=@requester WHERE ApprovalId=COALESCE(@approvalId,(SELECT target.ApprovalId FROM (SELECT a.ApprovalId FROM Approvals a JOIN DocumentVersions v ON v.VersionId=a.VersionId WHERE v.DocumentId=@id ORDER BY a.RequestedAt DESC LIMIT 1) target)) AND EXISTS(SELECT 1 FROM DocumentVersions checkVersion WHERE checkVersion.VersionId=Approvals.VersionId AND checkVersion.DocumentId=@id)", connection, tx);
        updateRequester.Parameters.AddRange(new MySqlParameter[] { P("@requester", requestedById.Value), P("@approvalId", request.ApprovalId), P("@id", id) });
        if (await updateRequester.ExecuteNonQueryAsync(ct) == 0) return Results.NotFound();
    }
    await AuditAsync(connection, actor, id, "DocumentAttributionCorrected", new { request.OwnerExternalId, request.ApprovalId, request.RequestedByExternalId }, ct, tx);
    await tx.CommitAsync(ct);
    return Results.NoContent();
}).RequireAuthorization(PermissionCodes.DocumentManage);
admin.MapPatch("/documents/{id:long}/visibility", async (long id, DocumentVisibilityUpdate request, ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var actor = await EnsureUserAsync(db, user, ct);
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    await using var update = new MySqlCommand("UPDATE Documents SET IsHidden=@hidden,UpdatedAt=UTC_TIMESTAMP(3) WHERE DocumentId=@id AND DeletedAt IS NULL", connection, tx);
    update.Parameters.AddRange(new MySqlParameter[] { P("@hidden", request.Hidden), P("@id", id) });
    if (await update.ExecuteNonQueryAsync(ct) == 0) return Results.NotFound();
    await AuditAsync(connection, actor, id, request.Hidden ? "DocumentHidden" : "DocumentUnhidden", new { request.Hidden }, ct, tx);
    await tx.CommitAsync(ct);
    return Results.NoContent();
}).RequireAuthorization(PermissionCodes.DocumentManage);
admin.MapDelete("/documents/{id:long}", async (long id, ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var actor = await EnsureUserAsync(db, user, ct);
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    await using var update = new MySqlCommand("UPDATE Documents SET DeletedAt=UTC_TIMESTAMP(3),UpdatedAt=UTC_TIMESTAMP(3) WHERE DocumentId=@id AND DeletedAt IS NULL", connection, tx);
    update.Parameters.Add(P("@id", id));
    if (await update.ExecuteNonQueryAsync(ct) == 0) return Results.NotFound();
    await using (var cancel = new MySqlCommand("UPDATE Approvals a JOIN DocumentVersions v ON v.VersionId=a.VersionId SET a.Decision='Cancelado',a.DecidedAt=UTC_TIMESTAMP(3),a.Comment='Cancelado pela exclusão administrativa do documento.' WHERE v.DocumentId=@id AND a.Decision='Pendente'", connection, tx))
    {
        cancel.Parameters.Add(P("@id", id));
        await cancel.ExecuteNonQueryAsync(ct);
    }
    await AuditAsync(connection, actor, id, "DocumentDeleted", new { deletedAt = DateTimeOffset.UtcNow }, ct, tx);
    await tx.CommitAsync(ct);
    return Results.NoContent();
}).RequireAuthorization(PermissionCodes.DocumentDelete);
admin.MapGet("/roles/{roleName}/document-scopes", async (string roleName, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    await using var connection = await db.OpenAsync(ct);
    await using var role = new MySqlCommand("SELECT RoleId FROM Roles WHERE Name=@name", connection);
    role.Parameters.Add(P("@name", roleName));
    var roleIdValue = await role.ExecuteScalarAsync(ct);
    if (roleIdValue is null) return Results.NotFound();
    var roleId = Convert.ToInt32(roleIdValue);
    var rules = await QueryAsync(db, "SELECT CategoryId,DocumentType FROM DocumentScopeRules WHERE RoleId=@role ORDER BY ScopeRuleId", [P("@role", roleId)], r => new { categoryId = r.IsDBNull(0) ? (int?)null : r.GetInt32(0), documentType = NullableString(r, 1) }, ct);
    return Results.Ok(new { restricted = rules.Count > 0, rules });
}).RequireAuthorization(PermissionCodes.PermissionManage);
admin.MapPut("/roles/{roleName}/document-scopes", async (string roleName, DocumentScopeUpdate request, ClaimsPrincipal actor, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var rules = request.Rules ?? [];
    if (rules.Length > 100 || rules.Any(rule => rule.CategoryId is null && string.IsNullOrWhiteSpace(rule.DocumentType) || !string.IsNullOrWhiteSpace(rule.DocumentType) && NormalizeType(rule.DocumentType) is not ("Manual" or "POP" or "Politica" or "Procedimento")))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["rules"] = ["Cada regra precisa de categoria e/ou tipo válidos; são permitidas até 100 regras."] });
    var actorId = await EnsureUserAsync(db, actor, ct);
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    await using var role = new MySqlCommand("SELECT RoleId FROM Roles WHERE Name=@name", connection, tx);
    role.Parameters.Add(P("@name", roleName));
    var roleValue = await role.ExecuteScalarAsync(ct);
    if (roleValue is null) return Results.NotFound();
    var roleId = Convert.ToInt32(roleValue);
    foreach (var rule in rules.Where(rule => rule.CategoryId.HasValue))
    {
        await using var category = new MySqlCommand("SELECT COUNT(*) FROM Categories WHERE CategoryId=@id AND IsActive=1", connection, tx);
        category.Parameters.Add(P("@id", rule.CategoryId!.Value));
        if (Convert.ToInt32(await category.ExecuteScalarAsync(ct)) == 0) return Results.ValidationProblem(new Dictionary<string, string[]> { ["rules"] = ["Uma das categorias selecionadas não está ativa."] });
    }
    await using (var clear = new MySqlCommand("DELETE FROM DocumentScopeRules WHERE RoleId=@role", connection, tx))
    {
        clear.Parameters.Add(P("@role", roleId));
        await clear.ExecuteNonQueryAsync(ct);
    }
    foreach (var rule in rules)
    {
        await using var insert = new MySqlCommand("INSERT INTO DocumentScopeRules(RoleId,CategoryId,DocumentType) VALUES(@role,@category,@type)", connection, tx);
        insert.Parameters.AddRange(new MySqlParameter[] { P("@role", roleId), P("@category", rule.CategoryId), P("@type", string.IsNullOrWhiteSpace(rule.DocumentType) ? null : NormalizeType(rule.DocumentType)) });
        await insert.ExecuteNonQueryAsync(ct);
    }
    await using (var audit = new MySqlCommand("INSERT INTO AuditLog(ActorUserId,EntityType,EntityId,Action,DetailsJson) VALUES(@actor,'Role',@id,'DocumentScopesUpdated',@details)", connection, tx))
    {
        audit.Parameters.AddRange(new MySqlParameter[] { P("@actor", actorId), P("@id", roleId), P("@details", JsonSerializer.Serialize(rules)) });
        await audit.ExecuteNonQueryAsync(ct);
    }
    await tx.CommitAsync(ct);
    return Results.Ok(new { restricted = rules.Length > 0, rules });
}).RequireAuthorization(PermissionCodes.PermissionManage);
admin.MapGet("/ldap-settings", async (DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var settings = await ReadLdapSettingsAsync(db, ct);
    if (settings is null) return Results.NotFound();
    var groupMappings = await QueryAsync(db, "SELECT GroupDn,RoleName FROM LdapRoleGroupMappings ORDER BY RoleName,GroupDn", null, r => new LdapRoleGroupMapping(r.GetString(0), r.GetString(1)), ct);
    return Results.Ok(new { settings.PrimaryHost, settings.SecondaryHost, settings.Port, settings.UserIdFormat, settings.BootstrapAdminExternalId, settings.BaseDn, settings.LoginAttribute, settings.BindUser, settings.AdminGroupDn, groupMappings, hasBindPassword = !string.IsNullOrEmpty(settings.BindPasswordProtected) });
}).RequireAuthorization(PermissionCodes.PermissionManage);
admin.MapGet("/ldap-groups", async (LdapAuthenticator ldap, IDataProtectionProvider protection, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var settings = await ReadLdapSettingsAsync(db, ct);
    if (settings is null || string.IsNullOrWhiteSpace(settings.BaseDn) || string.IsNullOrWhiteSpace(settings.BindUser) || string.IsNullOrWhiteSpace(settings.BindPasswordProtected))
        return Results.Problem("Configure Base DN, conta de consulta e senha antes de carregar os grupos do diretório.", statusCode: StatusCodes.Status400BadRequest);
    string bindPassword;
    try { bindPassword = protection.CreateProtector("AtlasTi.Ldap.BindPassword.v1").Unprotect(settings.BindPasswordProtected); }
    catch (System.Security.Cryptography.CryptographicException) { return Results.Problem("Não foi possível descriptografar a credencial da conta de consulta LDAP.", statusCode: StatusCodes.Status503ServiceUnavailable); }
    var result = ldap.GetGroups(bindPassword, settings);
    if (!result.Success) return Results.Problem("Não foi possível consultar os grupos. Confira o usuário, a senha e as permissões de leitura da conta de consulta.", statusCode: StatusCodes.Status503ServiceUnavailable);
    return Results.Ok(result.Groups);
}).RequireAuthorization(PermissionCodes.PermissionManage);
admin.MapPost("/ldap-test", async (LdapConnectionTestRequest request, LdapAuthenticator ldap, IDataProtectionProvider protection, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(request.PrimaryHost) || request.PrimaryHost.Trim().Length > 255 || request.SecondaryHost?.Trim().Length > 255 || request.Port is < 1 or > 65535 || string.IsNullOrWhiteSpace(request.BaseDn) || request.BaseDn.Length > 512 || string.IsNullOrWhiteSpace(request.BindUser) || request.BindUser.Length > 255)
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["settings"] = ["Informe servidor primário, porta, Base DN e conta de consulta para testar o LDAP."] });
    var bindPassword = request.BindPassword;
    if (string.IsNullOrWhiteSpace(bindPassword))
    {
        var current = await ReadLdapSettingsAsync(db, ct);
        if (string.IsNullOrWhiteSpace(current?.BindPasswordProtected))
            return Results.ValidationProblem(new Dictionary<string, string[]> { ["bindPassword"] = ["Informe a senha da conta de consulta para realizar o teste."] });
        try { bindPassword = protection.CreateProtector("AtlasTi.Ldap.BindPassword.v1").Unprotect(current.BindPasswordProtected); }
        catch (System.Security.Cryptography.CryptographicException) { return Results.Problem("Não foi possível descriptografar a credencial salva da conta de consulta.", statusCode: StatusCodes.Status503ServiceUnavailable); }
    }
    var hosts = new[] { request.PrimaryHost.Trim(), request.SecondaryHost?.Trim() }.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    var results = new List<(string Host, bool Success, int GroupCount)>();
    foreach (var host in hosts)
    {
        var testSettings = new LdapSettings(host!, null, request.Port, "{0}", string.Empty, request.BaseDn!.Trim(), "sAMAccountName", request.BindUser.Trim(), null, null);
        var test = ldap.GetGroups(bindPassword!, testSettings);
        results.Add((host!, test.Success, test.Groups.Count));
    }
    return Results.Ok(new { success = results.Count > 0 && results.All(x => x.Success), endpoints = results.Select(x => new { host = x.Host, success = x.Success, groupCount = x.GroupCount }) });
}).RequireAuthorization(PermissionCodes.PermissionManage);
admin.MapPut("/ldap-settings", async (LdapSettingsUpdate request, ClaimsPrincipal actor, IDataProtectionProvider protection, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var groupMappings = (request.GroupMappings ?? []).Where(x => !string.IsNullOrWhiteSpace(x.GroupDn))
        .Concat(string.IsNullOrWhiteSpace(request.AdminGroupDn) ? [] : [new LdapRoleGroupMapping(request.AdminGroupDn!, "Administrador")])
        .Select(x => new LdapRoleGroupMapping(x.GroupDn.Trim(), x.RoleName.Trim()))
        .DistinctBy(x => $"{x.GroupDn.ToUpperInvariant()}|{x.RoleName}", StringComparer.Ordinal).ToArray();
    var allowedJitRoles = (await QueryAsync(db, "SELECT Name FROM Roles", null, r => r.GetString(0), ct)).ToArray();
    if (string.IsNullOrWhiteSpace(request.PrimaryHost) || request.PrimaryHost.Trim().Length > 255 ||
        request.SecondaryHost?.Trim().Length > 255 || request.Port is < 1 or > 65535 ||
        string.IsNullOrWhiteSpace(request.UserIdFormat) || !request.UserIdFormat.Contains("{0}", StringComparison.Ordinal) ||
        string.IsNullOrWhiteSpace(request.BootstrapAdminExternalId) || request.BootstrapAdminExternalId.Trim().Length > 200 ||
        request.BaseDn?.Length > 512 || request.BindUser?.Length > 255 || groupMappings.Any(x => x.GroupDn.Length > 512 || !allowedJitRoles.Contains(x.RoleName, StringComparer.Ordinal)) || !System.Text.RegularExpressions.Regex.IsMatch(request.LoginAttribute ?? "", "^[A-Za-z][A-Za-z0-9-]{0,79}$"))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["settings"] = ["Informe o servidor primário, porta válida e login administrador; cada host pode ter até 255 caracteres."] });
    try { _ = string.Format(System.Globalization.CultureInfo.InvariantCulture, request.UserIdFormat, "usuario"); }
    catch (FormatException) { return Results.ValidationProblem(new Dictionary<string, string[]> { ["userIdFormat"] = ["O formato precisa conter o marcador {0}."] }); }

    var actorId = await EnsureUserAsync(db, actor, ct);
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    if (groupMappings.Length > 0)
    {
        if (string.IsNullOrWhiteSpace(request.BaseDn) || string.IsNullOrWhiteSpace(request.BindUser))
            return Results.ValidationProblem(new Dictionary<string, string[]> { ["groupMappings"] = ["O mapeamento JIT exige Base DN e conta de consulta LDAP."] });
        var hasNewPassword = !string.IsNullOrWhiteSpace(request.BindPassword);
        if (!hasNewPassword)
        {
            await using var secretCheck = new MySqlCommand("SELECT BindPasswordProtected FROM LdapSettings WHERE SettingsId=1", connection, tx);
            hasNewPassword = !string.IsNullOrWhiteSpace(Convert.ToString(await secretCheck.ExecuteScalarAsync(ct)));
        }
        if (!hasNewPassword)
            return Results.ValidationProblem(new Dictionary<string, string[]> { ["groupMappings"] = ["O mapeamento JIT exige a senha criptografada da conta de consulta LDAPS."] });
    }
    long? newAdminId = null;
    await using (var findAdmin = new MySqlCommand("SELECT UserId FROM Users WHERE ExternalId=@externalId AND IsActive=1", connection, tx))
    {
        findAdmin.Parameters.Add(P("@externalId", request.BootstrapAdminExternalId.Trim()));
        var result = await findAdmin.ExecuteScalarAsync(ct);
        if (result is null) return Results.ValidationProblem(new Dictionary<string, string[]> { ["bootstrapAdminExternalId"] = ["O novo administrador precisa entrar no sistema ao menos uma vez antes da transferência."] });
        newAdminId = Convert.ToInt64(result);
    }
    string? oldAdminExternalId;
    await using (var readCurrent = new MySqlCommand("SELECT BootstrapAdminExternalId FROM LdapSettings WHERE SettingsId=1", connection, tx))
        oldAdminExternalId = Convert.ToString(await readCurrent.ExecuteScalarAsync(ct));
    if (string.IsNullOrWhiteSpace(oldAdminExternalId)) return Results.Conflict(new { error = "Configuração LDAP não inicializada." });

    if (!oldAdminExternalId.Equals(request.BootstrapAdminExternalId.Trim(), StringComparison.OrdinalIgnoreCase))
    {
        await using var removeOld = new MySqlCommand("DELETE ur FROM UserRoles ur JOIN Users u ON u.UserId=ur.UserId JOIN Roles r ON r.RoleId=ur.RoleId WHERE u.ExternalId=@externalId AND r.Name='Administrador'", connection, tx);
        removeOld.Parameters.Add(P("@externalId", oldAdminExternalId));
        await removeOld.ExecuteNonQueryAsync(ct);
        await using var grantNew = new MySqlCommand("INSERT IGNORE INTO UserRoles(UserId,RoleId,AssignedByUserId) SELECT @userId,RoleId,@actor FROM Roles WHERE Name='Administrador'", connection, tx);
        grantNew.Parameters.AddRange(new MySqlParameter[] { P("@userId", newAdminId), P("@actor", actorId) });
        await grantNew.ExecuteNonQueryAsync(ct);
    }
    await using (var clearMappings = new MySqlCommand("DELETE FROM LdapRoleGroupMappings", connection, tx)) await clearMappings.ExecuteNonQueryAsync(ct);
    await using (var clearJitRoles = new MySqlCommand("DELETE FROM UserRoles WHERE AssignmentSource='LdapGroup'", connection, tx)) await clearJitRoles.ExecuteNonQueryAsync(ct);
    foreach (var mapping in groupMappings)
    {
        await using var addMapping = new MySqlCommand("INSERT INTO LdapRoleGroupMappings(GroupDn,RoleName) VALUES(@dn,@role)", connection, tx);
        addMapping.Parameters.AddRange(new MySqlParameter[] { P("@dn", mapping.GroupDn), P("@role", mapping.RoleName) });
        await addMapping.ExecuteNonQueryAsync(ct);
    }
    var protectedSecret = string.IsNullOrWhiteSpace(request.BindPassword) ? null : protection.CreateProtector("AtlasTi.Ldap.BindPassword.v1").Protect(request.BindPassword!);
    await using (var update = new MySqlCommand("UPDATE LdapSettings SET PrimaryHost=@primary,SecondaryHost=@secondary,Port=@port,UserIdFormat=@format,BaseDn=@baseDn,LoginAttribute=@loginAttribute,BindUser=@bindUser,BindPasswordProtected=COALESCE(@bindSecret,BindPasswordProtected),BootstrapAdminExternalId=@admin,AdminGroupDn=NULL,UpdatedAt=UTC_TIMESTAMP(3),UpdatedByUserId=@actor WHERE SettingsId=1", connection, tx))
    {
        update.Parameters.AddRange(new MySqlParameter[]
        {
            P("@primary", request.PrimaryHost.Trim()), P("@secondary", EmptyToNull(request.SecondaryHost)), P("@port", request.Port),
            P("@format", request.UserIdFormat.Trim()), P("@baseDn", EmptyToNull(request.BaseDn)), P("@loginAttribute", (request.LoginAttribute ?? "sAMAccountName").Trim()),
            P("@bindUser", EmptyToNull(request.BindUser)), P("@bindSecret", protectedSecret), P("@admin", request.BootstrapAdminExternalId.Trim()), P("@actor", actorId)
        });
        if (await update.ExecuteNonQueryAsync(ct) == 0) return Results.Conflict(new { error = "Configuração LDAP não inicializada." });
    }
    await using (var audit = new MySqlCommand("INSERT INTO AuditLog(ActorUserId,EntityType,EntityId,Action,DetailsJson) VALUES(@actor,'SystemSetting',1,'LdapSettingsChanged',@details)", connection, tx))
    {
        audit.Parameters.AddRange(new MySqlParameter[]
        {
            P("@actor", actorId), P("@details", JsonSerializer.Serialize(new
            {
                primaryHost = request.PrimaryHost.Trim(), secondaryHost = EmptyToNull(request.SecondaryHost), request.Port,
                userIdFormat = request.UserIdFormat.Trim(), oldBootstrapAdmin = oldAdminExternalId,
                newBootstrapAdmin = request.BootstrapAdminExternalId.Trim()
            }))
        });
        await audit.ExecuteNonQueryAsync(ct);
    }
    await tx.CommitAsync(ct);
    return Results.Ok(new { primaryHost = request.PrimaryHost.Trim(), secondaryHost = EmptyToNull(request.SecondaryHost), request.Port, userIdFormat = request.UserIdFormat.Trim(), bootstrapAdminExternalId = request.BootstrapAdminExternalId.Trim() });
}).RequireAuthorization(PermissionCodes.PermissionManage);
admin.MapGet("/users", async (bool? deleted, ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    if (!await HasAnyPermissionAsync(db, user, [PermissionCodes.UserView, PermissionCodes.PermissionManage], ct)) return Results.Forbid();
    const string sql = "SELECT u.UserId,u.ExternalId,u.DisplayName,u.Email,u.IsActive,GROUP_CONCAT(DISTINCT CASE WHEN ur.AssignmentSource='Manual' THEN r.Name END ORDER BY r.Name SEPARATOR ',') manualRoles,GROUP_CONCAT(DISTINCT CASE WHEN ur.AssignmentSource='LdapGroup' THEN r.Name END ORDER BY r.Name SEPARATOR ',') jitRoles,u.CreatedAt,u.LastLoginAt,u.DeletedAt FROM Users u LEFT JOIN UserRoles ur ON ur.UserId=u.UserId LEFT JOIN Roles r ON r.RoleId=ur.RoleId WHERE (@deleted=1 AND u.DeletedAt IS NOT NULL) OR (@deleted=0 AND u.DeletedAt IS NULL) GROUP BY u.UserId,u.ExternalId,u.DisplayName,u.Email,u.IsActive,u.CreatedAt,u.LastLoginAt,u.DeletedAt ORDER BY u.DisplayName";
    return Results.Ok(await QueryAsync(db, sql, [P("@deleted", deleted == true)], r => new { id = r.GetInt64(0), externalId = r.GetString(1), name = r.GetString(2), email = r.GetString(3), isActive = r.GetBoolean(4), manualRoles = NullableString(r, 5)?.Split(',', StringSplitOptions.RemoveEmptyEntries) ?? [], jitRoles = NullableString(r, 6)?.Split(',', StringSplitOptions.RemoveEmptyEntries) ?? [], createdAt = ReadUtc(r, 7), lastLoginAt = ReadUtc(r, 8), deletedAt = ReadUtc(r, 9) }, ct));
});
admin.MapGet("/users/{id:long}", async (long id, ClaimsPrincipal actor, LdapAuthenticator ldap, IDataProtectionProvider protection, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    if (!await HasAnyPermissionAsync(db, actor, [PermissionCodes.UserView], ct)) return Results.Forbid();
    var found = await QueryAsync(db, "SELECT UserId,ExternalId,DisplayName,Email,IsActive,CreatedAt,LastLoginAt,DeletedAt FROM Users WHERE UserId=@id", [P("@id", id)], r => new { id = r.GetInt64(0), externalId = r.GetString(1), name = r.GetString(2), email = r.GetString(3), isActive = r.GetBoolean(4), createdAt = ReadUtc(r, 5), lastLoginAt = ReadUtc(r, 6), deletedAt = ReadUtc(r, 7) }, ct);
    var profile = found.FirstOrDefault();
    if (profile is null) return Results.NotFound();
    var roles = await QueryAsync(db, "SELECT r.Name,ur.AssignmentSource FROM UserRoles ur JOIN Roles r ON r.RoleId=ur.RoleId WHERE ur.UserId=@id ORDER BY r.Name", [P("@id", id)], r => new { name = r.GetString(0), source = r.GetString(1) }, ct);
    var permissions = await QueryAsync(db, "SELECT DISTINCT p.Code FROM UserRoles ur JOIN RolePermissions rp ON rp.RoleId=ur.RoleId JOIN Permissions p ON p.PermissionId=rp.PermissionId WHERE ur.UserId=@id ORDER BY p.Code", [P("@id", id)], r => r.GetString(0), ct);
    var stats = (await QueryAsync(db, "SELECT (SELECT COUNT(*) FROM Documents WHERE OwnerUserId=@id AND DeletedAt IS NULL),(SELECT COUNT(*) FROM DocumentVersions WHERE CreatedByUserId=@id),(SELECT COUNT(*) FROM Approvals WHERE RequestedByUserId=@id),(SELECT COUNT(*) FROM Approvals WHERE ApproverUserId=@id AND Decision<>'Pendente')", [P("@id", id)], r => new { documents = r.GetInt64(0), versions = r.GetInt64(1), submitted = r.GetInt64(2), decided = r.GetInt64(3) }, ct)).First();
    var activity = await QueryAsync(db, "SELECT Action,EntityType,EntityId,OccurredAt FROM AuditLog WHERE ActorUserId=@id ORDER BY OccurredAt DESC,AuditLogId DESC LIMIT 15", [P("@id", id)], r => new { action = r.GetString(0), entityType = r.GetString(1), entityId = r.GetInt64(2), occurredAt = ReadUtc(r, 3) }, ct);
    // Dados do diretório (cargo, departamento, telefone): consulta opcional, não impede a abertura do perfil.
    Dictionary<string, string?>? directory = null;
    try
    {
        var settings = await ReadLdapSettingsAsync(db, ct);
        if (settings is not null && !string.IsNullOrWhiteSpace(settings.BindUser) && !string.IsNullOrWhiteSpace(settings.BindPasswordProtected) && !string.IsNullOrWhiteSpace(settings.BaseDn))
        {
            var bindPassword = protection.CreateProtector("AtlasTi.Ldap.BindPassword.v1").Unprotect(settings.BindPasswordProtected);
            var result = ldap.ReadUserProfile(profile.externalId, bindPassword, settings);
            if (result.Success && result.Attributes.Count > 0)
                directory = new[] { "title", "department", "company", "telephoneNumber", "mobile", "physicalDeliveryOfficeName", "employeeID" }.Where(result.Attributes.ContainsKey).ToDictionary(key => key, key => result.Attributes[key]);
        }
    }
    catch (Exception) { directory = null; }
    return Results.Ok(new { profile.id, profile.externalId, profile.name, profile.email, profile.isActive, profile.createdAt, profile.lastLoginAt, profile.deletedAt, roles, permissions, stats, activity, directory });
});
admin.MapPut("/users", async (UserUpsert request, ClaimsPrincipal actor, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(request.ExternalId) || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.DisplayName))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["user"] = ["ExternalId, email e nome são obrigatórios."] });
    var roles = (request.Roles ?? []).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    var actorId = await EnsureUserAsync(db, actor, ct);
    var actorIsMaster = await HasRoleAsync(db, actor, PermissionCodes.MasterRole, ct);
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    long? existingId = null;
    await using (var existing = new MySqlCommand("SELECT UserId,DeletedAt FROM Users WHERE ExternalId=@externalId", connection, tx))
    {
        existing.Parameters.Add(P("@externalId", request.ExternalId.Trim()));
        await using var reader = await existing.ExecuteReaderAsync(ct);
        if (await reader.ReadAsync(ct))
        {
            existingId = reader.GetInt64(0);
            if (!reader.IsDBNull(1)) return Results.Conflict(new { error = "Este usuário foi excluído. Restaure-o antes de alterar os grupos." });
        }
    }
    var wantsMaster = roles.Contains(PermissionCodes.MasterRole, StringComparer.OrdinalIgnoreCase);
    var hadMaster = false;
    if (existingId is not null)
    {
        await using var hadCheck = new MySqlCommand("SELECT COUNT(*) FROM UserRoles ur JOIN Roles r ON r.RoleId=ur.RoleId WHERE ur.UserId=@id AND r.Name='Master' AND ur.AssignmentSource='Manual'", connection, tx);
        hadCheck.Parameters.Add(P("@id", existingId));
        hadMaster = Convert.ToInt32(await hadCheck.ExecuteScalarAsync(ct)) > 0;
    }
    // Somente um Master concede ou retira o papel Master.
    if (wantsMaster != hadMaster && !actorIsMaster) return Results.Json(new { error = "Somente um Master pode conceder ou retirar o papel Master." }, statusCode: StatusCodes.Status403Forbidden);
    if (existingId == actorId && !request.IsActive) return Results.Conflict(new { error = "Você não pode desativar a própria conta." });
    await using var command = new MySqlCommand("INSERT INTO Users(ExternalId,DisplayName,Email,IsActive) VALUES(@externalId,@name,@email,@active) ON DUPLICATE KEY UPDATE DisplayName=VALUES(DisplayName),Email=VALUES(Email),IsActive=VALUES(IsActive)", connection, tx);
    command.Parameters.AddRange(new MySqlParameter[] {P("@externalId", request.ExternalId.Trim()), P("@name", request.DisplayName.Trim()), P("@email", request.Email.Trim()), P("@active", request.IsActive)});
    await command.ExecuteNonQueryAsync(ct);
    await using var userLookup = new MySqlCommand("SELECT UserId FROM Users WHERE ExternalId=@externalId", connection, tx);
    userLookup.Parameters.Add(P("@externalId", request.ExternalId.Trim()));
    var userId = Convert.ToInt64(await userLookup.ExecuteScalarAsync(ct));
    // Troca somente os papéis administrados manualmente; atribuições JIT do LDAP continuam vigentes.
    await using (var clear = new MySqlCommand("DELETE FROM UserRoles WHERE UserId=@userId AND AssignmentSource='Manual'", connection, tx))
    {
        clear.Parameters.Add(P("@userId", userId));
        await clear.ExecuteNonQueryAsync(ct);
    }
    foreach (var role in roles)
    {
        await using (var known = new MySqlCommand("SELECT COUNT(*) FROM Roles WHERE Name=@role", connection, tx))
        {
            known.Parameters.Add(P("@role", role));
            if (Convert.ToInt32(await known.ExecuteScalarAsync(ct)) == 0) return Results.ValidationProblem(new Dictionary<string, string[]> { ["roles"] = [$"Papel desconhecido: {role}"] });
        }
        // Papel que o usuário já recebe por grupo do AD vira manual (a decisão do administrador prevalece e não some quando o grupo mudar).
        await using (var promote = new MySqlCommand("UPDATE UserRoles SET AssignmentSource='Manual',AssignedByUserId=@actor,AssignedAt=UTC_TIMESTAMP(3) WHERE UserId=@userId AND AssignmentSource<>'Manual' AND RoleId=(SELECT RoleId FROM Roles WHERE Name=@role)", connection, tx))
        {
            promote.Parameters.AddRange(new MySqlParameter[] {P("@userId", userId), P("@actor", actorId), P("@role", role)});
            await promote.ExecuteNonQueryAsync(ct);
        }
        await using var assign = new MySqlCommand("INSERT INTO UserRoles(UserId,RoleId,AssignedByUserId,AssignmentSource) SELECT @userId,r.RoleId,@actor,'Manual' FROM Roles r WHERE r.Name=@role AND NOT EXISTS(SELECT 1 FROM UserRoles x WHERE x.UserId=@userId AND x.RoleId=r.RoleId)", connection, tx);
        assign.Parameters.AddRange(new MySqlParameter[] {P("@userId", userId), P("@actor", actorId), P("@role", role)});
        await assign.ExecuteNonQueryAsync(ct);
    }
    if (await CountActiveMastersAsync(connection, tx, ct) == 0) return Results.Conflict(new { error = "Precisa existir ao menos um usuário Master ativo." });
    await AuditAsync(connection, actorId, userId, "RolesUpdated", new { roles, request.IsActive }, ct, tx, "User");
    await tx.CommitAsync(ct);
    return Results.Ok(new { id = userId, request.ExternalId, Roles = roles });
}).RequireAuthorization(PermissionCodes.PermissionManage);
admin.MapDelete("/users/{id:long}", async (long id, ClaimsPrincipal actor, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var actorId = await EnsureUserAsync(db, actor, ct);
    if (actorId == id) return Results.Conflict(new { error = "Você não pode excluir a própria conta." });
    var actorIsMaster = await HasRoleAsync(db, actor, PermissionCodes.MasterRole, ct);
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    var targetIsMaster = false;
    await using (var target = new MySqlCommand("SELECT COUNT(*) FROM UserRoles ur JOIN Roles r ON r.RoleId=ur.RoleId JOIN Users u ON u.UserId=ur.UserId WHERE ur.UserId=@id AND r.Name='Master' AND u.IsActive=1", connection, tx))
    {
        target.Parameters.Add(P("@id", id));
        targetIsMaster = Convert.ToInt32(await target.ExecuteScalarAsync(ct)) > 0;
    }
    if (targetIsMaster && !actorIsMaster) return Results.Json(new { error = "Somente um Master pode excluir outro Master." }, statusCode: StatusCodes.Status403Forbidden);
    if (targetIsMaster && await CountActiveMastersAsync(connection, tx, ct) <= 1) return Results.Conflict(new { error = "Este é o último Master ativo; defina outro Master antes de excluí-lo." });
    await using (var delete = new MySqlCommand("UPDATE Users SET IsActive=0,DeletedAt=UTC_TIMESTAMP(3) WHERE UserId=@id AND DeletedAt IS NULL", connection, tx))
    {
        delete.Parameters.Add(P("@id", id));
        if (await delete.ExecuteNonQueryAsync(ct) == 0) return Results.NotFound();
    }
    await using (var roles = new MySqlCommand("DELETE FROM UserRoles WHERE UserId=@id", connection, tx))
    {
        roles.Parameters.Add(P("@id", id));
        await roles.ExecuteNonQueryAsync(ct);
    }
    await AuditAsync(connection, actorId, id, "UserDeleted", new { deletedAt = DateTimeOffset.UtcNow }, ct, tx, "User");
    await tx.CommitAsync(ct);
    return Results.NoContent();
}).RequireAuthorization(PermissionCodes.UserDelete);
admin.MapPost("/users/{id:long}/restore", async (long id, ClaimsPrincipal actor, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var actorId = await EnsureUserAsync(db, actor, ct);
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    await using (var restore = new MySqlCommand("UPDATE Users SET IsActive=1,DeletedAt=NULL WHERE UserId=@id AND DeletedAt IS NOT NULL", connection, tx))
    {
        restore.Parameters.Add(P("@id", id));
        if (await restore.ExecuteNonQueryAsync(ct) == 0) return Results.NotFound();
    }
    await AuditAsync(connection, actorId, id, "UserRestored", new { restoredAt = DateTimeOffset.UtcNow }, ct, tx, "User");
    await tx.CommitAsync(ct);
    return Results.NoContent();
}).RequireAuthorization(PermissionCodes.UserDelete);
admin.MapGet("/audit", async (string? entity, int? take, ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    if (!await HasAnyPermissionAsync(db, user, [PermissionCodes.UserView], ct)) return Results.Forbid();
    const string sql = "SELECT a.AuditLogId,a.EntityType,a.EntityId,a.Action,a.OccurredAt,actor.DisplayName,CASE a.EntityType WHEN 'User' THEN tu.DisplayName WHEN 'Document' THEN td.Title WHEN 'Role' THEN tr.Name WHEN 'Category' THEN tc.Name WHEN 'System' THEN ts.Name END FROM AuditLog a LEFT JOIN Users actor ON actor.UserId=a.ActorUserId LEFT JOIN Users tu ON a.EntityType='User' AND tu.UserId=a.EntityId LEFT JOIN Documents td ON a.EntityType='Document' AND td.DocumentId=a.EntityId LEFT JOIN Roles tr ON a.EntityType='Role' AND tr.RoleId=a.EntityId LEFT JOIN Categories tc ON a.EntityType='Category' AND tc.CategoryId=a.EntityId LEFT JOIN Systems ts ON a.EntityType='System' AND ts.SystemId=a.EntityId WHERE (@entity IS NULL OR a.EntityType=@entity) ORDER BY a.OccurredAt DESC,a.AuditLogId DESC LIMIT @take";
    return Results.Ok(await QueryAsync(db, sql, [P("@entity", EmptyToNull(entity)), P("@take", Math.Clamp(take ?? 60, 1, 200))], r => new { id = r.GetInt64(0), entityType = r.GetString(1), entityId = r.GetInt64(2), action = r.GetString(3), occurredAt = ReadUtc(r, 4), actor = NullableString(r, 5), target = NullableString(r, 6) }, ct));
});
admin.MapGet("/roles", async (ClaimsPrincipal user, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    if (!await HasAnyPermissionAsync(db, user, [PermissionCodes.UserView, PermissionCodes.PermissionManage], ct)) return Results.Forbid();
    const string sql = "SELECT r.Name,r.Description,p.Code FROM Roles r LEFT JOIN RolePermissions rp ON rp.RoleId=r.RoleId LEFT JOIN Permissions p ON p.PermissionId=rp.PermissionId ORDER BY r.Name,p.Code";
    var rows = await QueryAsync(db, sql, null, r => new { role = r.GetString(0), description = NullableString(r, 1), permission = NullableString(r, 2) }, ct);
    return Results.Ok(rows.GroupBy(x => x.role).Select(g => new { role = g.Key, description = g.First().description, permissions = g.Where(x => x.permission is not null).Select(x => x.permission!).ToArray() }));
});
admin.MapPost("/roles", async (RoleUpsert request, ClaimsPrincipal actor, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var name = request.Name?.Trim();
    var permissions = request.Permissions ?? [];
    if (string.IsNullOrWhiteSpace(name) || name.Length > 60) return Results.ValidationProblem(new Dictionary<string, string[]> { ["name"] = ["Informe um nome de grupo com até 60 caracteres."] });
    if (permissions.Except(PermissionCodes.All, StringComparer.Ordinal).Any()) return Results.ValidationProblem(new Dictionary<string, string[]> { ["permissions"] = ["A lista contém permissões desconhecidas."] });
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    await using (var exists = new MySqlCommand("SELECT COUNT(*) FROM Roles WHERE Name=@name", connection, tx))
    {
        exists.Parameters.Add(P("@name", name));
        if (Convert.ToInt32(await exists.ExecuteScalarAsync(ct)) > 0) return Results.Conflict(new { error = "Já existe um grupo com esse nome." });
    }
    await using (var create = new MySqlCommand("INSERT INTO Roles(Name,Description) VALUES(@name,@description)", connection, tx))
    {
        create.Parameters.AddRange(new MySqlParameter[] { P("@name", name), P("@description", EmptyToNull(request.Description)) });
        await create.ExecuteNonQueryAsync(ct);
    }
    foreach (var permission in permissions.Distinct(StringComparer.Ordinal))
    {
        await using var assign = new MySqlCommand("INSERT IGNORE INTO RolePermissions(RoleId,PermissionId) SELECT r.RoleId,p.PermissionId FROM Roles r CROSS JOIN Permissions p WHERE r.Name=@role AND p.Code=@permission", connection, tx);
        assign.Parameters.AddRange(new MySqlParameter[] { P("@role", name), P("@permission", permission) });
        await assign.ExecuteNonQueryAsync(ct);
    }
    await AuditRoleAsync(db, actor, connection, tx, name, "RoleCreated", new { permissions }, ct);
    await tx.CommitAsync(ct);
    return Results.Created($"/api/admin/roles/{Uri.EscapeDataString(name)}", new { role = name, permissions });
}).RequireAuthorization(PermissionCodes.PermissionManage);
admin.MapPut("/roles/{roleName}", async (string roleName, RoleUpsert request, ClaimsPrincipal actor, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    var name = request.Name?.Trim();
    var permissions = request.Permissions ?? [];
    if (string.IsNullOrWhiteSpace(name) || name.Length > 60) return Results.ValidationProblem(new Dictionary<string, string[]> { ["name"] = ["Informe um nome de grupo com até 60 caracteres."] });
    if (permissions.Except(PermissionCodes.All, StringComparer.Ordinal).Any()) return Results.ValidationProblem(new Dictionary<string, string[]> { ["permissions"] = ["A lista contém permissões desconhecidas."] });
    if (roleName.Equals(PermissionCodes.MasterRole, StringComparison.OrdinalIgnoreCase) && (!name.Equals(roleName, StringComparison.Ordinal) || !PermissionCodes.All.All(p => permissions.Contains(p, StringComparer.Ordinal))))
        return Results.Conflict(new { error = "O grupo Master não pode ser renomeado nem perder permissões." });
    if (roleName.Equals("Administrador", StringComparison.OrdinalIgnoreCase) && !name.Equals(roleName, StringComparison.Ordinal))
        return Results.Conflict(new { error = "O grupo Administrador não pode ser renomeado." });
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    await using (var collision = new MySqlCommand("SELECT COUNT(*) FROM Roles WHERE Name=@name AND Name<>@old", connection, tx))
    {
        collision.Parameters.AddRange(new MySqlParameter[] { P("@name", name), P("@old", roleName) });
        if (Convert.ToInt32(await collision.ExecuteScalarAsync(ct)) > 0) return Results.Conflict(new { error = "Já existe um grupo com esse nome." });
    }
    await using (var update = new MySqlCommand("UPDATE Roles SET Name=@name,Description=@description WHERE Name=@old", connection, tx))
    {
        update.Parameters.AddRange(new MySqlParameter[] { P("@name", name), P("@description", EmptyToNull(request.Description)), P("@old", roleName) });
        if (await update.ExecuteNonQueryAsync(ct) == 0) return Results.NotFound();
    }
    if (!name.Equals(roleName, StringComparison.Ordinal))
    {
        await using var updateJit = new MySqlCommand("UPDATE LdapRoleGroupMappings SET RoleName=@name WHERE RoleName=@old", connection, tx);
        updateJit.Parameters.AddRange(new MySqlParameter[] { P("@name", name), P("@old", roleName) });
        await updateJit.ExecuteNonQueryAsync(ct);
    }
    await using (var clear = new MySqlCommand("DELETE rp FROM RolePermissions rp JOIN Roles r ON r.RoleId=rp.RoleId WHERE r.Name=@name", connection, tx))
    {
        clear.Parameters.Add(P("@name", name));
        await clear.ExecuteNonQueryAsync(ct);
    }
    foreach (var permission in permissions.Distinct(StringComparer.Ordinal))
    {
        await using var assign = new MySqlCommand("INSERT IGNORE INTO RolePermissions(RoleId,PermissionId) SELECT r.RoleId,p.PermissionId FROM Roles r CROSS JOIN Permissions p WHERE r.Name=@role AND p.Code=@permission", connection, tx);
        assign.Parameters.AddRange(new MySqlParameter[] { P("@role", name), P("@permission", permission) });
        await assign.ExecuteNonQueryAsync(ct);
    }
    await AuditRoleAsync(db, actor, connection, tx, name, "RoleUpdated", new { permissions }, ct);
    await tx.CommitAsync(ct);
    return Results.Ok(new { role = name, request.Description, permissions });
}).RequireAuthorization(PermissionCodes.PermissionManage);
admin.MapPut("/roles/{roleName}/permissions", async (string roleName, RolePermissionsUpdate request, ClaimsPrincipal actor, DatabaseConnectionFactory db, CancellationToken ct) =>
{
    if (roleName.Equals(PermissionCodes.MasterRole, StringComparison.OrdinalIgnoreCase) && !PermissionCodes.All.All(permission => request.Permissions.Contains(permission, StringComparer.Ordinal)))
        return Results.Conflict(new { error = "O papel Master deve conservar todas as permissões para evitar bloqueio administrativo." });
    if (request.Permissions.Except(PermissionCodes.All, StringComparer.Ordinal).Any())
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["permissions"] = ["A lista contém uma permissão desconhecida."] });
    await using var connection = await db.OpenAsync(ct);
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    await using (var roleCheck = new MySqlCommand("SELECT RoleId FROM Roles WHERE Name=@name", connection, tx))
    {
        roleCheck.Parameters.Add(P("@name", roleName));
        if (await roleCheck.ExecuteScalarAsync(ct) is null) return Results.NotFound();
    }
    await using (var clear = new MySqlCommand("DELETE rp FROM RolePermissions rp JOIN Roles r ON r.RoleId=rp.RoleId WHERE r.Name=@name", connection, tx))
    {
        clear.Parameters.Add(P("@name", roleName));
        await clear.ExecuteNonQueryAsync(ct);
    }
    foreach (var permission in request.Permissions.Distinct(StringComparer.Ordinal))
    {
        await using var add = new MySqlCommand("INSERT IGNORE INTO RolePermissions(RoleId,PermissionId) SELECT r.RoleId,p.PermissionId FROM Roles r CROSS JOIN Permissions p WHERE r.Name=@role AND p.Code=@permission", connection, tx);
        add.Parameters.AddRange(new MySqlParameter[] {P("@role", roleName), P("@permission", permission)});
        await add.ExecuteNonQueryAsync(ct);
    }
    await AuditRoleAsync(db, actor, connection, tx, roleName, "RoleUpdated", new { request.Permissions }, ct);
    await tx.CommitAsync(ct);
    return Results.Ok(new { role = roleName, request.Permissions });
}).RequireAuthorization(PermissionCodes.PermissionManage);

app.Run();

static async Task<List<T>> QueryAsync<T>(DatabaseConnectionFactory db, string sql, MySqlParameter[]? parameters, Func<MySqlDataReader, T> map, CancellationToken ct)
{
    await using var connection = await db.OpenAsync(ct);
    return await QueryConnectionAsync(connection, sql, parameters, map, ct);
}
static async Task<LdapSettings?> ReadLdapSettingsAsync(DatabaseConnectionFactory db, CancellationToken ct)
{
    await using var connection = await db.OpenAsync(ct);
    await using var command = new MySqlCommand("SELECT PrimaryHost,SecondaryHost,Port,UserIdFormat,BootstrapAdminExternalId,BaseDn,LoginAttribute,BindUser,BindPasswordProtected,AdminGroupDn FROM LdapSettings WHERE SettingsId=1", connection);
    await using var reader = await command.ExecuteReaderAsync(ct);
    if (!await reader.ReadAsync(ct)) return null;
    return new LdapSettings(reader.GetString(0), NullableString(reader, 1), reader.GetInt32(2), reader.GetString(3), reader.GetString(4), NullableString(reader, 5), reader.GetString(6), NullableString(reader, 7), NullableString(reader, 8), NullableString(reader, 9));
}
static async Task<List<T>> QueryConnectionAsync<T>(MySqlConnection connection, string sql, MySqlParameter[]? parameters, Func<MySqlDataReader, T> map, CancellationToken ct)
{
    await using var command = new MySqlCommand(sql, connection);
    if (parameters is not null) command.Parameters.AddRange(parameters);
    await using var reader = await command.ExecuteReaderAsync(ct);
    var rows = new List<T>();
    while (await reader.ReadAsync(ct)) rows.Add(map(reader));
    return rows;
}
static MySqlParameter P(string name, object? value) => new(name, value ?? DBNull.Value);
static string? NullableString(MySqlDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
static string? EmptyToNull(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
static IEnumerable<string> ParseFormTags(string? value) => string.IsNullOrWhiteSpace(value) ? [] : value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
static string? NormalizeState(string? value) => value?.Trim() switch { "Revisão" => "Revisao", "Publicado" => "Publicado", "Obsoleto" => "Obsoleto", "Inativo" => "Inativo", null or "" => null, _ => "__invalid__" };
static string NormalizeType(string value) => value.Trim() switch { "Política" => "Politica", "Manual" => "Manual", "POP" => "POP", "Procedimento" => "Procedimento", _ => value.Trim() };
static Dictionary<string, string[]>? ValidateDocument(string title, string type)
{
    var errors = new Dictionary<string, string[]>();
    if (string.IsNullOrWhiteSpace(title) || title.Length > 240) errors["title"] = ["Informe um título de até 240 caracteres."];
    if (!new[] { "Manual", "POP", "Política", "Politica", "Procedimento" }.Contains(type)) errors["documentType"] = ["Tipo inválido. Use Manual, POP, Política ou Procedimento."];
    return errors.Count == 0 ? null : errors;
}
static async Task InsertTagsAsync(MySqlConnection connection, MySqlTransaction tx, long id, IEnumerable<string> tags, CancellationToken ct)
{
    foreach (var tag in tags.Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Take(30))
    {
        await using var command = new MySqlCommand("INSERT INTO DocumentTags(DocumentId,Tag) VALUES(@id,@tag)", connection, tx);
        command.Parameters.AddRange(new MySqlParameter[] {P("@id", id), P("@tag", tag[..Math.Min(80, tag.Length)])});
        await command.ExecuteNonQueryAsync(ct);
    }
}
static async Task<long> EnsureUserAsync(DatabaseConnectionFactory db, ClaimsPrincipal principal, CancellationToken ct, bool refreshProfile = false)
{
    var externalId = principal.FindFirstValue("oid") ?? principal.FindFirstValue("sub") ?? throw new UnauthorizedAccessException("Token sem identificador de usuário.");
    var displayName = principal.FindFirstValue("name") ?? principal.FindFirstValue("preferred_username") ?? externalId;
    if (displayName.Length > 160) displayName = displayName[..160];
    var directoryEmail = principal.FindFirstValue("email");
    await using var connection = await db.OpenAsync(ct);

    async Task<long?> FindUserAsync()
    {
        await using var find = new MySqlCommand("SELECT UserId FROM Users WHERE ExternalId=@externalId", connection);
        find.Parameters.Add(P("@externalId", externalId));
        var found = await find.ExecuteScalarAsync(ct);
        return found is null or DBNull ? null : Convert.ToInt64(found);
    }
    async Task<bool> EmailInUseAsync(string email, long? exceptUserId)
    {
        await using var taken = new MySqlCommand("SELECT COUNT(*) FROM Users WHERE Email=@email AND UserId<>@userId", connection);
        taken.Parameters.AddRange(new MySqlParameter[] { P("@email", email), P("@userId", exceptUserId ?? 0L) });
        return Convert.ToInt32(await taken.ExecuteScalarAsync(ct)) > 0;
    }

    // Nome e e-mail só são gravados na criação e no login (refreshProfile). Antes, toda requisição autenticada
    // sobrescrevia o nome do autor pelo texto do token e o e-mail por um valor fictício.
    var userId = await FindUserAsync();
    string? emailToStore = null;
    if (!string.IsNullOrWhiteSpace(directoryEmail) && (refreshProfile || userId is null))
    {
        var candidate = directoryEmail.Trim();
        if (candidate.Length <= 320 && !await EmailInUseAsync(candidate, userId)) emailToStore = candidate;
    }
    if (userId is null)
    {
        try
        {
            await using var insert = new MySqlCommand("INSERT INTO Users(ExternalId,DisplayName,Email) VALUES(@externalId,@name,@email)", connection);
            insert.Parameters.AddRange(new MySqlParameter[] { P("@externalId", externalId), P("@name", displayName), P("@email", emailToStore ?? $"{externalId}@unknown.invalid") });
            await insert.ExecuteNonQueryAsync(ct);
        }
        catch (MySqlException) { /* Requisição concorrente já criou o registro; a leitura abaixo confirma. */ }
        userId = await FindUserAsync() ?? throw new InvalidOperationException("Não foi possível provisionar o usuário no Atlas TI.");
        if (!refreshProfile) return userId.Value;
    }
    if (refreshProfile)
    {
        await using var update = new MySqlCommand("UPDATE Users SET DisplayName=@name,Email=COALESCE(@email,Email),LastLoginAt=UTC_TIMESTAMP(3) WHERE UserId=@userId", connection);
        update.Parameters.AddRange(new MySqlParameter[] { P("@name", displayName), P("@email", emailToStore), P("@userId", userId.Value) });
        await update.ExecuteNonQueryAsync(ct);
    }
    return userId.Value;
}
static async Task SyncLdapRolesAsync(DatabaseConnectionFactory db, long userId, IEnumerable<string> roleNames, CancellationToken ct)
{
    await using var connection = await db.OpenAsync(ct);
    // Transação: sem ela, uma requisição concorrente do mesmo usuário podia ver zero papéis entre o DELETE e os INSERTs.
    await using var tx = (MySqlTransaction)await connection.BeginTransactionAsync(ct);
    await using (var clear = new MySqlCommand("DELETE FROM UserRoles WHERE UserId=@userId AND AssignmentSource='LdapGroup'", connection, tx))
    {
        clear.Parameters.Add(P("@userId", userId));
        await clear.ExecuteNonQueryAsync(ct);
    }
    foreach (var roleName in roleNames.Distinct(StringComparer.OrdinalIgnoreCase))
    {
        await using var assign = new MySqlCommand("INSERT IGNORE INTO UserRoles(UserId,RoleId,AssignmentSource) SELECT @userId,RoleId,'LdapGroup' FROM Roles WHERE Name=@role", connection, tx);
        assign.Parameters.AddRange(new MySqlParameter[] { P("@userId", userId), P("@role", roleName) });
        await assign.ExecuteNonQueryAsync(ct);
    }
    await tx.CommitAsync(ct);
}
static string MakeSlug(string value)
{
    var decomposed = value.Normalize(NormalizationForm.FormD);
    var withoutMarks = new string(decomposed.Where(ch => System.Globalization.CharUnicodeInfo.GetUnicodeCategory(ch) != System.Globalization.UnicodeCategory.NonSpacingMark).ToArray());
    return System.Text.RegularExpressions.Regex.Replace(withoutMarks.ToLowerInvariant(), "[^a-z0-9]+", "-").Trim('-');
}
static async Task<bool> HasAnyPermissionAsync(DatabaseConnectionFactory db, ClaimsPrincipal principal, string[] permissions, CancellationToken ct)
{
    var externalId = principal.FindFirstValue("oid") ?? principal.FindFirstValue("sub");
    if (externalId is null || permissions.Length == 0) return false;
    var parameters = permissions.Select((_, index) => $"@permission{index}").ToArray();
    await using var connection = await db.OpenAsync(ct);
    await using var command = new MySqlCommand($"SELECT CASE WHEN EXISTS(SELECT 1 FROM Users u JOIN UserRoles ur ON ur.UserId=u.UserId JOIN RolePermissions rp ON rp.RoleId=ur.RoleId JOIN Permissions p ON p.PermissionId=rp.PermissionId WHERE u.ExternalId=@id AND u.IsActive=1 AND p.Code IN ({string.Join(',', parameters)})) THEN 1 ELSE 0 END", connection);
    command.Parameters.Add(P("@id", externalId));
    for (var index = 0; index < permissions.Length; index++) command.Parameters.Add(P(parameters[index], permissions[index]));
    return Convert.ToInt32(await command.ExecuteScalarAsync(ct)) == 1;
}

static DateTime? ReadUtc(MySqlDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Utc);
static async Task<bool> HasRoleAsync(DatabaseConnectionFactory db, ClaimsPrincipal principal, string roleName, CancellationToken ct)
{
    var externalId = principal.FindFirstValue("oid") ?? principal.FindFirstValue("sub");
    if (externalId is null) return false;
    await using var connection = await db.OpenAsync(ct);
    await using var command = new MySqlCommand("SELECT COUNT(*) FROM Users u JOIN UserRoles ur ON ur.UserId=u.UserId JOIN Roles r ON r.RoleId=ur.RoleId WHERE u.ExternalId=@id AND u.IsActive=1 AND u.DeletedAt IS NULL AND r.Name=@role", connection);
    command.Parameters.AddRange(new MySqlParameter[] { P("@id", externalId), P("@role", roleName) });
    return Convert.ToInt32(await command.ExecuteScalarAsync(ct)) > 0;
}
static async Task<int> CountActiveMastersAsync(MySqlConnection connection, MySqlTransaction tx, CancellationToken ct)
{
    await using var command = new MySqlCommand("SELECT COUNT(DISTINCT u.UserId) FROM Users u JOIN UserRoles ur ON ur.UserId=u.UserId JOIN Roles r ON r.RoleId=ur.RoleId WHERE r.Name='Master' AND u.IsActive=1 AND u.DeletedAt IS NULL", connection, tx);
    return Convert.ToInt32(await command.ExecuteScalarAsync(ct));
}
static async Task AuditRoleAsync(DatabaseConnectionFactory db, ClaimsPrincipal actor, MySqlConnection connection, MySqlTransaction tx, string roleName, string action, object details, CancellationToken ct)
{
    var actorId = await EnsureUserAsync(db, actor, ct);
    await using var command = new MySqlCommand("INSERT INTO AuditLog(ActorUserId,EntityType,EntityId,Action,DetailsJson) SELECT @actor,'Role',RoleId,@action,@details FROM Roles WHERE Name=@name", connection, tx);
    command.Parameters.AddRange(new MySqlParameter[] { P("@actor", actorId), P("@action", action), P("@details", JsonSerializer.Serialize(details)), P("@name", roleName) });
    await command.ExecuteNonQueryAsync(ct);
}
static async Task AuditAsync(MySqlConnection connection, long actor, long entityId, string action, object details, CancellationToken ct, MySqlTransaction? transaction = null, string entityType = "Document")
{
    await using var command = new MySqlCommand("INSERT INTO AuditLog(ActorUserId,EntityType,EntityId,Action,DetailsJson) VALUES(@actor,@type,@id,@action,@details)", connection, transaction);
    command.Parameters.AddRange(new MySqlParameter[] {P("@actor", actor), P("@type", entityType), P("@id", entityId), P("@action", action), P("@details", JsonSerializer.Serialize(details))});
    await command.ExecuteNonQueryAsync(ct);
}

record DocumentSummary(long Id, string Code, string Title, string? Summary, string Type, string State, string Category, string? System, string? Version, DateTime? UpdatedAt, string Owner, bool Hidden)
{
    public static DocumentSummary Read(MySqlDataReader r) => new(r.GetInt64(0), r.GetString(1), r.GetString(2), ReadNullable(r, 3), r.GetString(4), r.GetString(5), r.GetString(6), ReadNullable(r, 7), r.IsDBNull(8) ? null : $"v{r.GetInt32(8)}.{r.GetInt32(9)}", r.IsDBNull(10) ? null : r.GetDateTime(10), r.GetString(11), r.GetBoolean(12));
    private static string? ReadNullable(MySqlDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
}
record DocumentVersionDto(long Id, string Version, string ChangeSummary, DateTime CreatedAt, bool IsPublished, string? OriginalFileName, string? ContentType, long? FileSizeBytes);
record DocumentDetail(long Id, string Code, string Title, string? Summary, string Type, string State, int CategoryId, string Category, int? SystemId, string? System, long OwnerId, string Owner, DateTime UpdatedAt, long? CurrentVersionId, string? Version, string? ChangeSummary, string? Content, DateTime? VersionCreatedAt, string? OriginalFileName, string? ContentType, long? FileSizeBytes, IReadOnlyList<DocumentVersionDto> Versions, IReadOnlyList<string> Tags)
{
    public string? OwnerExternalId { get; init; }
    public string? SubmittedBy { get; init; }
    public string? SubmittedByExternalId { get; init; }
    public static DocumentDetail Read(MySqlDataReader r) => new(r.GetInt64(0), r.GetString(1), r.GetString(2), ReadNullable(r, 3), r.GetString(4), r.GetString(5), r.GetInt32(6), r.GetString(7), r.IsDBNull(8) ? null : r.GetInt32(8), ReadNullable(r, 9), r.GetInt64(10), r.GetString(11), r.GetDateTime(12), r.IsDBNull(13) ? null : r.GetInt64(13), r.IsDBNull(14) ? null : $"v{r.GetInt32(14)}.{r.GetInt32(15)}", ReadNullable(r, 16), ReadNullable(r, 17), r.IsDBNull(18) ? null : r.GetDateTime(18), ReadNullable(r, 19), ReadNullable(r, 20), r.IsDBNull(21) ? null : r.GetInt64(21), [], []);
    private static string? ReadNullable(MySqlDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
}
