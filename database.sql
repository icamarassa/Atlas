-- Atlas TI schema for MySQL 8.4 / MariaDB 11.8 (InnoDB, utf8mb4).
CREATE TABLE Users (
    UserId BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ExternalId VARCHAR(200) NOT NULL,
    DisplayName VARCHAR(160) NOT NULL,
    Email VARCHAR(320) NOT NULL,
    IsActive BOOLEAN NOT NULL DEFAULT TRUE,
    CreatedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    LastLoginAt DATETIME(3) NULL,
    DeletedAt DATETIME(3) NULL,
    UNIQUE KEY UQ_Users_ExternalId (ExternalId),
    UNIQUE KEY UQ_Users_Email (Email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE Roles (
    RoleId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    Name VARCHAR(60) NOT NULL UNIQUE,
    Description VARCHAR(240) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE Permissions (
    PermissionId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    Code VARCHAR(80) NOT NULL UNIQUE,
    Description VARCHAR(240) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE RolePermissions (
    RoleId INT NOT NULL,
    PermissionId INT NOT NULL,
    PRIMARY KEY (RoleId, PermissionId),
    CONSTRAINT FK_RolePermissions_Roles FOREIGN KEY (RoleId) REFERENCES Roles(RoleId),
    CONSTRAINT FK_RolePermissions_Permissions FOREIGN KEY (PermissionId) REFERENCES Permissions(PermissionId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE UserRoles (
    UserId BIGINT NOT NULL,
    RoleId INT NOT NULL,
    AssignedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    AssignedByUserId BIGINT NULL,
    AssignmentSource VARCHAR(32) NOT NULL DEFAULT 'Manual',
    PRIMARY KEY (UserId, RoleId),
    CONSTRAINT FK_UserRoles_Users FOREIGN KEY (UserId) REFERENCES Users(UserId),
    CONSTRAINT FK_UserRoles_Roles FOREIGN KEY (RoleId) REFERENCES Roles(RoleId),
    CONSTRAINT FK_UserRoles_AssignedBy FOREIGN KEY (AssignedByUserId) REFERENCES Users(UserId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE LdapSettings (
    SettingsId TINYINT NOT NULL PRIMARY KEY CHECK (SettingsId=1),
    PrimaryHost VARCHAR(255) NOT NULL,
    SecondaryHost VARCHAR(255) NULL,
    Port INT NOT NULL DEFAULT 636 CHECK (Port BETWEEN 1 AND 65535),
    UserIdFormat VARCHAR(200) NOT NULL DEFAULT '{0}',
    BaseDn VARCHAR(512) NULL,
    LoginAttribute VARCHAR(80) NOT NULL DEFAULT 'sAMAccountName',
    BindUser VARCHAR(255) NULL,
    BindPasswordProtected TEXT NULL,
    AdminGroupDn VARCHAR(512) NULL,
    BootstrapAdminExternalId VARCHAR(200) NOT NULL,
    UpdatedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UpdatedByUserId BIGINT NULL,
    CONSTRAINT FK_LdapSettings_UpdatedBy FOREIGN KEY (UpdatedByUserId) REFERENCES Users(UserId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE Categories (
    CategoryId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    Name VARCHAR(120) NOT NULL UNIQUE,
    Slug VARCHAR(140) NOT NULL UNIQUE,
    Description VARCHAR(400) NULL,
    IsActive BOOLEAN NOT NULL DEFAULT TRUE,
    CreatedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE Systems (
    SystemId INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    Name VARCHAR(160) NOT NULL UNIQUE,
    OwnerTeam VARCHAR(160) NULL,
    Description VARCHAR(500) NULL,
    IsActive BOOLEAN NOT NULL DEFAULT TRUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE Documents (
    DocumentId BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    DocumentCode VARCHAR(13) NULL UNIQUE,
    Title VARCHAR(240) NOT NULL,
    Summary VARCHAR(1000) NULL,
    DocumentType VARCHAR(30) NOT NULL,
    CategoryId INT NOT NULL,
    SystemId INT NULL,
    LifecycleState VARCHAR(20) NOT NULL DEFAULT 'Revisao',
    CurrentVersionId BIGINT NULL,
    OwnerUserId BIGINT NOT NULL,
    CreatedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UpdatedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    DeletedAt DATETIME(3) NULL,
    IsHidden BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT CK_Documents_Type CHECK (DocumentType IN ('Manual','POP','Politica','Procedimento')),
    CONSTRAINT CK_Documents_State CHECK (LifecycleState IN ('Publicado','Obsoleto','Inativo','Revisao')),
    CONSTRAINT FK_Documents_Category FOREIGN KEY (CategoryId) REFERENCES Categories(CategoryId),
    CONSTRAINT FK_Documents_System FOREIGN KEY (SystemId) REFERENCES Systems(SystemId),
    CONSTRAINT FK_Documents_Owner FOREIGN KEY (OwnerUserId) REFERENCES Users(UserId),
    INDEX IX_Documents_State_Category_Updated (LifecycleState, CategoryId, UpdatedAt),
    INDEX IX_Documents_System_State (SystemId, LifecycleState)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE DocumentVersions (
    VersionId BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    DocumentId BIGINT NOT NULL,
    VersionMajor INT NOT NULL,
    VersionMinor INT NOT NULL,
    ChangeSummary VARCHAR(1000) NOT NULL,
    Content LONGTEXT NULL,
    StorageUri VARCHAR(1000) NULL,
    ContentHash BINARY(32) NULL,
    OriginalFileName VARCHAR(255) NULL,
    ContentType VARCHAR(127) NULL,
    FileSizeBytes BIGINT UNSIGNED NULL,
    CreatedByUserId BIGINT NOT NULL,
    CreatedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    IsPublished BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE KEY UQ_DocumentVersions_Number (DocumentId, VersionMajor, VersionMinor),
    INDEX IX_DocumentVersions_Document_Created (DocumentId, CreatedAt),
    CONSTRAINT CK_DocumentVersions_Number CHECK (VersionMajor >= 1 AND VersionMinor >= 0),
    CONSTRAINT FK_DocumentVersions_Document FOREIGN KEY (DocumentId) REFERENCES Documents(DocumentId),
    CONSTRAINT FK_DocumentVersions_CreatedBy FOREIGN KEY (CreatedByUserId) REFERENCES Users(UserId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
ALTER TABLE Documents ADD CONSTRAINT FK_Documents_CurrentVersion FOREIGN KEY (CurrentVersionId) REFERENCES DocumentVersions(VersionId);

CREATE TABLE Approvals (
    ApprovalId BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    VersionId BIGINT NOT NULL,
    RequestedByUserId BIGINT NOT NULL,
    ApproverUserId BIGINT NULL,
    Decision VARCHAR(20) NOT NULL DEFAULT 'Pendente',
    RequestedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    DecidedAt DATETIME(3) NULL,
    Comment VARCHAR(1000) NULL,
    CONSTRAINT CK_Approvals_Decision CHECK (Decision IN ('Pendente','Aprovado','Rejeitado','Cancelado')),
    CONSTRAINT FK_Approvals_Version FOREIGN KEY (VersionId) REFERENCES DocumentVersions(VersionId),
    CONSTRAINT FK_Approvals_RequestedBy FOREIGN KEY (RequestedByUserId) REFERENCES Users(UserId),
    CONSTRAINT FK_Approvals_Approver FOREIGN KEY (ApproverUserId) REFERENCES Users(UserId),
    INDEX IX_Approvals_Pending (Decision, ApproverUserId, RequestedAt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE DocumentTags (
    DocumentId BIGINT NOT NULL,
    Tag VARCHAR(80) NOT NULL,
    PRIMARY KEY (DocumentId, Tag),
    CONSTRAINT FK_DocumentTags_Document FOREIGN KEY (DocumentId) REFERENCES Documents(DocumentId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE AuditLog (
    AuditLogId BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ActorUserId BIGINT NULL,
    EntityType VARCHAR(60) NOT NULL,
    EntityId BIGINT NOT NULL,
    Action VARCHAR(80) NOT NULL,
    DetailsJson JSON NULL,
    OccurredAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT FK_AuditLog_Actor FOREIGN KEY (ActorUserId) REFERENCES Users(UserId),
    INDEX IX_AuditLog_Entity_Date (EntityType, EntityId, OccurredAt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE CategoryRolePermissions (
    CategoryId INT NOT NULL,
    RoleId INT NOT NULL,
    PermissionId INT NOT NULL,
    PRIMARY KEY (CategoryId, RoleId, PermissionId),
    CONSTRAINT FK_CategoryRolePermissions_Category FOREIGN KEY (CategoryId) REFERENCES Categories(CategoryId),
    CONSTRAINT FK_CategoryRolePermissions_Role FOREIGN KEY (RoleId) REFERENCES Roles(RoleId),
    CONSTRAINT FK_CategoryRolePermissions_Permission FOREIGN KEY (PermissionId) REFERENCES Permissions(PermissionId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE DocumentScopeRules (
    ScopeRuleId BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    RoleId INT NOT NULL,
    CategoryId INT NULL,
    DocumentType VARCHAR(30) NULL,
    CreatedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    CONSTRAINT FK_DocumentScopeRules_Role FOREIGN KEY (RoleId) REFERENCES Roles(RoleId) ON DELETE CASCADE,
    CONSTRAINT FK_DocumentScopeRules_Category FOREIGN KEY (CategoryId) REFERENCES Categories(CategoryId),
    CONSTRAINT CK_DocumentScopeRules_Filter CHECK (CategoryId IS NOT NULL OR DocumentType IS NOT NULL),
    INDEX IX_DocumentScopeRules_Role (RoleId, CategoryId, DocumentType)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE LdapRoleGroupMappings (
    MappingId BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    GroupDn VARCHAR(512) NOT NULL,
    RoleName VARCHAR(60) NOT NULL,
    CreatedAt DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY UQ_LdapRoleGroupMappings_Group_Role (GroupDn, RoleName),
    INDEX IX_LdapRoleGroupMappings_Role (RoleName)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO Roles (Name, Description) VALUES
 ('Master','Administrador do sistema: usuários, grupos, integrações e todas as funções'),
 ('Administrador','Gerencia documentos, categorias e sistemas, sem administrar usuários nem integrações'),
 ('Editor','Cria e atualiza documentos'),
 ('Aprovador','Aprova ou rejeita versões submetidas'),
 ('Leitor','Consulta documentos publicados');

INSERT INTO Permissions (Code, Description) VALUES
 ('document.read','Visualizar documentos'),
 ('document.create','Criar documentos'),
 ('document.edit','Editar metadados e criar versões'),
 ('document.submit','Enviar versões para aprovação'),
 ('document.approve','Aprovar ou rejeitar versões'),
 ('document.change_state','Alterar estado do documento'),
 ('document.manage','Ocultar documentos e corrigir autoria'),
 ('document.delete','Excluir documentos'),
 ('catalog.manage','Criar e editar categorias e sistemas'),
 ('user.view','Visualizar usuários e perfis'),
 ('user.delete','Excluir usuários'),
 ('permission.manage','Gerenciar grupos, permissões, atribuições e o Active Directory');

INSERT INTO RolePermissions (RoleId, PermissionId)
SELECT r.RoleId, p.PermissionId FROM Roles AS r CROSS JOIN Permissions AS p
WHERE r.Name='Master'
   OR (r.Name='Administrador' AND p.Code IN ('document.read','document.create','document.edit','document.submit','document.approve','document.change_state','document.manage','document.delete','catalog.manage'))
   OR (r.Name='Editor' AND p.Code IN ('document.read','document.create','document.edit','document.submit'))
   OR (r.Name='Aprovador' AND p.Code IN ('document.read','document.approve','document.change_state'))
   OR (r.Name='Leitor' AND p.Code='document.read');

INSERT INTO Categories (Name, Slug) VALUES
 ('Infraestrutura e redes','infraestrutura-redes'),
 ('Backup e recuperação','backup-recuperacao'),
 ('Segurança da informação','seguranca-informacao'),
 ('Sistemas corporativos','sistemas-corporativos'),
 ('Suporte e service desk','suporte-service-desk');
