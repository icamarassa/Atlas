using MySqlConnector;

namespace AtlasTi.Api;

public static class DatabaseBootstrapper
{
    public static async Task InitializeAsync(IConfiguration configuration, ILogger logger)
    {
        var connectionString = configuration.GetConnectionString("AtlasTi")
            ?? throw new InvalidOperationException("Configure ConnectionStrings:AtlasTi.");
        await using var database = new MySqlConnection(connectionString);
        for (var attempt = 1; ; attempt++)
        {
            try { await database.OpenAsync(); break; }
            catch (MySqlException) when (attempt < 13) { await Task.Delay(TimeSpan.FromSeconds(5)); }
        }

        await using (var exists = new MySqlCommand("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='Users'", database))
        {
            if (Convert.ToInt32(await exists.ExecuteScalarAsync()) == 0)
            {
                var path = Path.Combine(AppContext.BaseDirectory, "database.sql");
                if (!File.Exists(path)) throw new FileNotFoundException("database.sql was not copied beside the API binaries.", path);
                var script = await File.ReadAllTextAsync(path);
                foreach (var statement in script.Split(';').Where(sql => !string.IsNullOrWhiteSpace(sql)))
                {
                    await using var command = new MySqlCommand(statement, database) { CommandTimeout = 120 };
                    await command.ExecuteNonQueryAsync();
                }
                logger.LogInformation("Atlas TI schema and initial catalog data created in MariaDB/MySQL.");
            }
            else logger.LogInformation("Atlas TI database already has a schema; no bootstrap changes were applied.");
        }

        await using (var hiddenColumn = new MySqlCommand("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='Documents' AND column_name='IsHidden'", database))
        {
            if (Convert.ToInt32(await hiddenColumn.ExecuteScalarAsync()) == 0)
            {
                await using var addHidden = new MySqlCommand("ALTER TABLE Documents ADD COLUMN IsHidden BOOLEAN NOT NULL DEFAULT FALSE", database);
                await addHidden.ExecuteNonQueryAsync();
            }
        }

        foreach (var (column, definition) in new (string Column, string Definition)[]
        {
            ("BaseDn", "VARCHAR(512) NULL"),
            ("LoginAttribute", "VARCHAR(80) NOT NULL DEFAULT 'sAMAccountName'"),
            ("BindUser", "VARCHAR(255) NULL"),
            ("BindPasswordProtected", "TEXT NULL"),
            ("AdminGroupDn", "VARCHAR(512) NULL")
        })
        {
            await using var check = new MySqlCommand("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='LdapSettings' AND column_name=@column", database);
            check.Parameters.AddWithValue("@column", column);
            if (Convert.ToInt32(await check.ExecuteScalarAsync()) != 0) continue;
            await using var alter = new MySqlCommand($"ALTER TABLE LdapSettings ADD COLUMN `{column}` {definition}", database);
            await alter.ExecuteNonQueryAsync();
            logger.LogInformation("Applied Atlas TI schema update for LdapSettings.{Column}.", column);
        }

        await using (var check = new MySqlCommand("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='UserRoles' AND column_name='AssignmentSource'", database))
        {
            if (Convert.ToInt32(await check.ExecuteScalarAsync()) == 0)
            {
                await using var alter = new MySqlCommand("ALTER TABLE UserRoles ADD COLUMN AssignmentSource VARCHAR(32) NOT NULL DEFAULT 'Manual'", database);
                await alter.ExecuteNonQueryAsync();
                logger.LogInformation("Applied Atlas TI schema update for UserRoles.AssignmentSource.");
            }
        }

        await using (var createScopes = new MySqlCommand("CREATE TABLE IF NOT EXISTS DocumentScopeRules (ScopeRuleId BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, RoleId INT NOT NULL, CategoryId INT NULL, DocumentType VARCHAR(30) NULL, CreatedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3), CONSTRAINT FK_DocumentScopeRules_Role FOREIGN KEY (RoleId) REFERENCES Roles(RoleId) ON DELETE CASCADE, CONSTRAINT FK_DocumentScopeRules_Category FOREIGN KEY (CategoryId) REFERENCES Categories(CategoryId), CONSTRAINT CK_DocumentScopeRules_Filter CHECK (CategoryId IS NOT NULL OR DocumentType IS NOT NULL), INDEX IX_DocumentScopeRules_Role (RoleId,CategoryId,DocumentType)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci", database))
            await createScopes.ExecuteNonQueryAsync();

        await using (var createMappings = new MySqlCommand("CREATE TABLE IF NOT EXISTS LdapRoleGroupMappings (MappingId BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, GroupDn VARCHAR(512) NOT NULL, RoleName VARCHAR(60) NOT NULL, CreatedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3), UNIQUE KEY UQ_LdapRoleGroupMappings_Group_Role (GroupDn,RoleName), INDEX IX_LdapRoleGroupMappings_Role (RoleName)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci", database))
            await createMappings.ExecuteNonQueryAsync();
        await using (var migrateLegacyMapping = new MySqlCommand("INSERT IGNORE INTO LdapRoleGroupMappings(GroupDn,RoleName) SELECT AdminGroupDn,'Administrador' FROM LdapSettings WHERE SettingsId=1 AND AdminGroupDn IS NOT NULL AND AdminGroupDn<>''", database))
            await migrateLegacyMapping.ExecuteNonQueryAsync();

        await ApplyAccessModelAsync(database, logger);

        var externalId = configuration["DatabaseBootstrap:AdminExternalId"];
        if (string.IsNullOrWhiteSpace(externalId)) return;
        var name = configuration["DatabaseBootstrap:AdminName"] ?? "Atlas TI Administrator";
        var email = configuration["DatabaseBootstrap:AdminEmail"] ?? $"{externalId}@unknown.invalid";
        await using (var existingAdminEmail = new MySqlCommand("SELECT Email FROM Users WHERE ExternalId=@externalId", database))
        {
            existingAdminEmail.Parameters.AddWithValue("@externalId", externalId);
            var savedEmail = Convert.ToString(await existingAdminEmail.ExecuteScalarAsync());
            if (!string.IsNullOrWhiteSpace(savedEmail))
                email = savedEmail;
            else
            {
                await using var emailOwner = new MySqlCommand("SELECT ExternalId FROM Users WHERE Email=@email LIMIT 1", database);
                emailOwner.Parameters.AddWithValue("@email", email);
                var ownerExternalId = Convert.ToString(await emailOwner.ExecuteScalarAsync());
                if (!string.IsNullOrWhiteSpace(ownerExternalId) && !ownerExternalId.Equals(externalId, StringComparison.OrdinalIgnoreCase))
                    email = $"atlas-admin-{Guid.NewGuid():N}@atlas.invalid";
            }
        }
        long userId;
        await using (var admin = new MySqlCommand("INSERT INTO Users(ExternalId,DisplayName,Email,IsActive) VALUES(@externalId,@name,@email,TRUE) ON DUPLICATE KEY UPDATE DisplayName=VALUES(DisplayName),Email=VALUES(Email),IsActive=TRUE", database))
        {
            admin.Parameters.AddRange(new MySqlParameter[] {new("@externalId", externalId), new("@name", name), new("@email", email)});
            await admin.ExecuteNonQueryAsync();
        }
        await using (var readId = new MySqlCommand("SELECT UserId FROM Users WHERE ExternalId=@externalId", database))
        {
            readId.Parameters.AddWithValue("@externalId", externalId);
            userId = Convert.ToInt64(await readId.ExecuteScalarAsync());
        }
        await using (var assign = new MySqlCommand("INSERT IGNORE INTO UserRoles(UserId,RoleId) SELECT @userId,RoleId FROM Roles WHERE Name='Master'", database))
        {
            assign.Parameters.AddWithValue("@userId", userId);
            await assign.ExecuteNonQueryAsync();
        }
        await using (var settings = new MySqlCommand("INSERT IGNORE INTO LdapSettings(SettingsId,PrimaryHost,SecondaryHost,Port,UserIdFormat,BootstrapAdminExternalId) VALUES(1,@primaryHost,@secondaryHost,@port,@format,@admin)", database))
        {
            settings.Parameters.AddRange(new MySqlParameter[]
            {
                new("@primaryHost", configuration["Ldap:Host"] ?? ""),
                new("@secondaryHost", string.IsNullOrWhiteSpace(configuration["Ldap:SecondaryHost"]) ? DBNull.Value : configuration["Ldap:SecondaryHost"]!),
                new("@port", configuration.GetValue("Ldap:Port", 636)),
                new("@format", configuration["Ldap:UserIdFormat"] ?? "{0}"),
                new("@admin", externalId)
            });
            await settings.ExecuteNonQueryAsync();
        }
        logger.LogWarning("Bootstrap administrator configured for external identity {ExternalId}.", externalId);
    }

    // Modelo de acesso: Master (administrador do sistema) acima de Administrador (privilégios de documentos e catálogo).
    // Idempotente: roda a cada inicialização e só reorganiza os papéis na primeira vez (quando o Master ainda não existe).
    private static async Task ApplyAccessModelAsync(MySqlConnection database, ILogger logger)
    {
        foreach (var (column, definition) in new (string Column, string Definition)[] { ("DeletedAt", "DATETIME(3) NULL"), ("LastLoginAt", "DATETIME(3) NULL") })
        {
            await using var check = new MySqlCommand("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='Users' AND column_name=@column", database);
            check.Parameters.AddWithValue("@column", column);
            if (Convert.ToInt32(await check.ExecuteScalarAsync()) != 0) continue;
            await using var alter = new MySqlCommand($"ALTER TABLE Users ADD COLUMN `{column}` {definition}", database);
            await alter.ExecuteNonQueryAsync();
            logger.LogInformation("Applied Atlas TI schema update for Users.{Column}.", column);
        }

        await using (var permissions = new MySqlCommand("INSERT IGNORE INTO Permissions(Code,Description) VALUES ('document.manage','Ocultar documentos e corrigir autoria'),('document.delete','Excluir documentos'),('catalog.manage','Criar e editar categorias e sistemas'),('user.view','Visualizar usuários e perfis'),('user.delete','Excluir usuários')", database))
            await permissions.ExecuteNonQueryAsync();
        await using (var describe = new MySqlCommand("UPDATE Permissions SET Description='Gerenciar grupos, permissões, atribuições e o Active Directory' WHERE Code='permission.manage'", database))
            await describe.ExecuteNonQueryAsync();

        long masterCount;
        await using (var exists = new MySqlCommand("SELECT COUNT(*) FROM Roles WHERE Name='Master'", database))
            masterCount = Convert.ToInt64(await exists.ExecuteScalarAsync());
        if (masterCount == 0)
        {
            await using (var create = new MySqlCommand("INSERT INTO Roles(Name,Description) VALUES('Master','Administrador do sistema: usuários, grupos, integrações e todas as funções')", database))
                await create.ExecuteNonQueryAsync();
            // Quem já administrava o sistema (atribuição manual) continua com acesso total; grupos do AD ficam no nível Administrador.
            await using (var promote = new MySqlCommand("INSERT IGNORE INTO UserRoles(UserId,RoleId,AssignmentSource) SELECT ur.UserId,m.RoleId,'Manual' FROM UserRoles ur JOIN Roles a ON a.RoleId=ur.RoleId AND a.Name='Administrador' JOIN Roles m ON m.Name='Master' WHERE ur.AssignmentSource='Manual'", database))
                await promote.ExecuteNonQueryAsync();
            await using (var anyMaster = new MySqlCommand("SELECT COUNT(*) FROM UserRoles ur JOIN Roles r ON r.RoleId=ur.RoleId WHERE r.Name='Master'", database))
            {
                if (Convert.ToInt64(await anyMaster.ExecuteScalarAsync()) == 0)
                {
                    await using var fallback = new MySqlCommand("INSERT IGNORE INTO UserRoles(UserId,RoleId,AssignmentSource) SELECT x.UserId,m.RoleId,'Manual' FROM (SELECT ur.UserId FROM UserRoles ur JOIN Roles a ON a.RoleId=ur.RoleId AND a.Name='Administrador' ORDER BY ur.UserId LIMIT 1) x JOIN Roles m ON m.Name='Master'", database);
                    if (await fallback.ExecuteNonQueryAsync() > 0) logger.LogWarning("Nenhum Master encontrado; o primeiro Administrador foi promovido a Master para evitar bloqueio administrativo.");
                }
            }
            await using (var clear = new MySqlCommand("DELETE rp FROM RolePermissions rp JOIN Roles r ON r.RoleId=rp.RoleId WHERE r.Name='Administrador'", database))
                await clear.ExecuteNonQueryAsync();
            await using (var grant = new MySqlCommand("INSERT IGNORE INTO RolePermissions(RoleId,PermissionId) SELECT r.RoleId,p.PermissionId FROM Roles r JOIN Permissions p ON p.Code IN ('document.read','document.create','document.edit','document.submit','document.approve','document.change_state','document.manage','document.delete','catalog.manage') WHERE r.Name='Administrador'", database))
                await grant.ExecuteNonQueryAsync();
            await using (var describeRole = new MySqlCommand("UPDATE Roles SET Description='Gerencia documentos, categorias e sistemas, sem administrar usuários nem integrações' WHERE Name='Administrador'", database))
                await describeRole.ExecuteNonQueryAsync();
            logger.LogWarning("Modelo de acesso atualizado: papel Master criado; Administrador passou a ser o nível de privilégios de documentos.");
        }
        // O Master sempre acumula todas as permissões, inclusive as criadas em versões futuras.
        await using (var master = new MySqlCommand("INSERT IGNORE INTO RolePermissions(RoleId,PermissionId) SELECT m.RoleId,p.PermissionId FROM Roles m CROSS JOIN Permissions p WHERE m.Name='Master'", database))
            await master.ExecuteNonQueryAsync();
    }
}
