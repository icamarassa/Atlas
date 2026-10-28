using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AtlasTi.Api;

public sealed class JwtTokenIssuer(IConfiguration configuration)
{
    private readonly string _issuer = configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("Configure Jwt:Issuer.");
    private readonly string _audience = configuration["Jwt:Audience"] ?? throw new InvalidOperationException("Configure Jwt:Audience.");
    private readonly int _lifetimeMinutes = Math.Clamp(configuration.GetValue("Jwt:LifetimeMinutes", 30), 5, 120);
    private readonly SymmetricSecurityKey _key = CreateKey(configuration["Jwt:SigningKey"]);

    public TokenValidationParameters ValidationParameters => new()
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = _key,
        ValidateIssuer = true,
        ValidIssuer = _issuer,
        ValidateAudience = true,
        ValidAudience = _audience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30),
        NameClaimType = "name",
        RoleClaimType = "roles"
    };

    public (string Token, DateTime ExpiresAtUtc) Create(string subject, string login, string displayName)
    {
        var expiresAt = DateTime.UtcNow.AddMinutes(_lifetimeMinutes);
        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: [new Claim("sub", subject), new Claim("name", displayName), new Claim("preferred_username", login)],
            notBefore: DateTime.UtcNow,
            expires: expiresAt,
            signingCredentials: new SigningCredentials(_key, SecurityAlgorithms.HmacSha256));
        return (new JwtSecurityTokenHandler().WriteToken(token), expiresAt);
    }

    private static SymmetricSecurityKey CreateKey(string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured)) throw new InvalidOperationException("Configure Jwt:SigningKey com uma chave aleatória Base64 de pelo menos 32 bytes.");
        byte[] bytes;
        try { bytes = Convert.FromBase64String(configured); }
        catch (FormatException exception) { throw new InvalidOperationException("Jwt:SigningKey precisa estar em Base64.", exception); }
        if (bytes.Length < 32) throw new InvalidOperationException("Jwt:SigningKey precisa ter no mínimo 32 bytes.");
        return new SymmetricSecurityKey(bytes);
    }
}
