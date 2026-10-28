using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace AtlasTi.Api;

public sealed record LdapSettings(string PrimaryHost, string? SecondaryHost, int Port, string UserIdFormat, string BootstrapAdminExternalId, string? BaseDn, string LoginAttribute, string? BindUser, string? BindPasswordProtected, string? AdminGroupDn);
public sealed record LdapDirectoryGroup(string Name, string DistinguishedName);

public sealed class LdapAuthenticator(ILogger<LdapAuthenticator> logger)
{
    private static readonly Regex LoginPattern = new("^[\\p{L}\\p{N}._@\\\\-]{1,120}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public string? FormatUserId(string? username, string format)
    {
        if (string.IsNullOrWhiteSpace(username) || !LoginPattern.IsMatch(username)) return null;
        try { return string.Format(System.Globalization.CultureInfo.InvariantCulture, format, username.Trim()); }
        catch (FormatException) { throw new InvalidOperationException("O formato de usuário LDAPS precisa conter o placeholder {0}."); }
    }

    public bool ValidateCredentials(string username, string password, LdapSettings settings, out string? userId)
    {
        userId = FormatUserId(username, settings.UserIdFormat);
        if (userId is null || string.IsNullOrEmpty(password)) return false;
        var hosts = new[] { settings.PrimaryHost, settings.SecondaryHost }
            .Where(host => !string.IsNullOrWhiteSpace(host)).Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var host in hosts)
        {
            try
            {
                var identifier = new LdapDirectoryIdentifier(host!, settings.Port, fullyQualifiedDnsHostName: false, connectionless: false);
                using var connection = new LdapConnection(identifier, new NetworkCredential(userId, password), AuthType.Basic)
                {
                    Timeout = TimeSpan.FromSeconds(5)
                };
                connection.SessionOptions.ProtocolVersion = 3;
                connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                connection.SessionOptions.SecureSocketLayer = true;
                connection.Bind();
                logger.LogInformation("LDAP login accepted by configured directory endpoint.");
                return true;
            }
            catch (LdapException exception) when (exception.ErrorCode == 49)
            {
                logger.LogInformation("LDAP credentials were rejected by a configured endpoint.");
                return false;
            }
            catch (Exception exception) when (exception is LdapException or DirectoryOperationException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException)
            {
                logger.LogWarning(exception, "LDAP endpoint {LdapHost} unavailable; trying the next configured endpoint.", host);
            }
        }
        return false;
    }

    public (bool Success, bool IsMember) IsDirectMemberOfGroup(string username, string bindPassword, LdapSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.BaseDn) || string.IsNullOrWhiteSpace(settings.BindUser) || string.IsNullOrWhiteSpace(settings.AdminGroupDn)) return (false, false);
        var attribute = Regex.IsMatch(settings.LoginAttribute, "^[A-Za-z][A-Za-z0-9-]{0,79}$") ? settings.LoginAttribute : "sAMAccountName";
        var safeUsername = EscapeFilterValue(NormalizeLogin(username, attribute));
        var safeGroupDn = EscapeFilterValue(settings.AdminGroupDn.Trim());
        var filter = $"(&({attribute}={safeUsername})(memberOf:1.2.840.113556.1.4.1941:={safeGroupDn}))";
        foreach (var host in new[] { settings.PrimaryHost, settings.SecondaryHost }.Where(h => !string.IsNullOrWhiteSpace(h)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var identifier = new LdapDirectoryIdentifier(host!, settings.Port, false, false);
                using var connection = new LdapConnection(identifier, new NetworkCredential(settings.BindUser, bindPassword), AuthType.Basic) { Timeout = TimeSpan.FromSeconds(5) };
                connection.SessionOptions.ProtocolVersion = 3;
                connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                connection.SessionOptions.SecureSocketLayer = true;
                connection.Bind();
                var request = new SearchRequest(settings.BaseDn, filter, SearchScope.Subtree, "distinguishedName") { SizeLimit = 1 };
                var response = (SearchResponse)connection.SendRequest(request);
                return (true, response.Entries.Count > 0);
            }
            catch (LdapException ex) when (ex.ErrorCode == 49)
            {
                logger.LogError("LDAP bind credentials for JIT group lookup were rejected.");
                return (false, false);
            }
            catch (Exception ex) when (ex is LdapException or DirectoryOperationException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException)
            {
                logger.LogWarning(ex, "LDAP group lookup failed on configured endpoint {LdapHost}.", host);
            }
        }
        return (false, false);
    }

    public (bool Success, List<LdapDirectoryGroup> Groups) GetGroups(string bindPassword, LdapSettings settings)
    {
        var groups = new List<LdapDirectoryGroup>();
        if (string.IsNullOrWhiteSpace(settings.BaseDn) || string.IsNullOrWhiteSpace(settings.BindUser)) return (false, groups);
        foreach (var host in new[] { settings.PrimaryHost, settings.SecondaryHost }.Where(h => !string.IsNullOrWhiteSpace(h)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var identifier = new LdapDirectoryIdentifier(host!, settings.Port, false, false);
                using var connection = new LdapConnection(identifier, new NetworkCredential(settings.BindUser, bindPassword), AuthType.Basic) { Timeout = TimeSpan.FromSeconds(10) };
                connection.SessionOptions.ProtocolVersion = 3;
                connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                connection.SessionOptions.SecureSocketLayer = true;
                connection.Bind();
                byte[] cookie = [];
                do
                {
                    var request = new SearchRequest(settings.BaseDn, "(&(objectCategory=group)(objectClass=group))", SearchScope.Subtree, "cn", "distinguishedName") { SizeLimit = 0 };
                    request.Controls.Add(new PageResultRequestControl(500) { Cookie = cookie });
                    var response = (SearchResponse)connection.SendRequest(request);
                    foreach (SearchResultEntry entry in response.Entries)
                    {
                        var dn = entry.DistinguishedName;
                        var name = entry.Attributes["cn"]?.GetValues(typeof(string)).Cast<string>().FirstOrDefault() ?? dn;
                        if (!string.IsNullOrWhiteSpace(dn)) groups.Add(new LdapDirectoryGroup(name, dn));
                        if (groups.Count >= 5000) break;
                    }
                    cookie = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault()?.Cookie ?? [];
                } while (cookie.Length > 0 && groups.Count < 5000);
                return (true, groups.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToList());
            }
            catch (LdapException ex) when (ex.ErrorCode == 49)
            {
                logger.LogError("LDAP bind credentials for group enumeration were rejected.");
                return (false, groups);
            }
            catch (Exception ex) when (ex is LdapException or DirectoryOperationException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException)
            {
                logger.LogWarning(ex, "LDAP group enumeration failed on configured endpoint {LdapHost}.", host);
            }
        }
        return (false, groups);
    }

    public (bool Success, Dictionary<string, string?> Attributes) ReadUserProfile(string username, string bindPassword, LdapSettings settings)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(settings.BaseDn) || string.IsNullOrWhiteSpace(settings.BindUser)) return (false, values);
        var loginAttribute = Regex.IsMatch(settings.LoginAttribute, "^[A-Za-z][A-Za-z0-9-]{0,79}$") ? settings.LoginAttribute : "sAMAccountName";
        var requested = new[] { "displayName", "givenName", "sn", "mail", "telephoneNumber", "mobile", "sAMAccountName", "userPrincipalName", "title", "department", "manager", "company", "physicalDeliveryOfficeName", "employeeID", "streetAddress", "l", "st", "employeeType", "birthDate" };
        var filter = $"({loginAttribute}={EscapeFilterValue(NormalizeLogin(username, loginAttribute))})";
        foreach (var host in new[] { settings.PrimaryHost, settings.SecondaryHost }.Where(h => !string.IsNullOrWhiteSpace(h)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var identifier = new LdapDirectoryIdentifier(host!, settings.Port, false, false);
                using var connection = new LdapConnection(identifier, new NetworkCredential(settings.BindUser, bindPassword), AuthType.Basic) { Timeout = TimeSpan.FromSeconds(8) };
                connection.SessionOptions.ProtocolVersion = 3;
                connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                connection.SessionOptions.SecureSocketLayer = true;
                connection.Bind();
                var request = new SearchRequest(settings.BaseDn, filter, SearchScope.Subtree, requested) { SizeLimit = 2 };
                var response = (SearchResponse)connection.SendRequest(request);
                if (response.Entries.Count != 1) return (true, values);
                var entry = response.Entries[0];
                foreach (var attribute in requested)
                {
                    var raw = entry.Attributes[attribute]?.GetValues(typeof(string)).Cast<string>().FirstOrDefault();
                    if (!string.IsNullOrWhiteSpace(raw)) values[attribute] = raw;
                }
                return (true, values);
            }
            catch (LdapException ex) when (ex.ErrorCode == 49)
            {
                logger.LogError("LDAP bind credentials for profile lookup were rejected.");
                return (false, values);
            }
            catch (Exception ex) when (ex is LdapException or DirectoryOperationException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException)
            {
                logger.LogWarning(ex, "LDAP profile lookup failed on configured endpoint {LdapHost}.", host);
            }
        }
        return (false, values);
    }

    // Quem entra como "dominio\ana" ou "ana@dominio" precisa ser pesquisado como "ana" quando o atributo de login é sAMAccountName;
    // sem isso a consulta de grupos (JIT) e de perfil não encontra o usuário e ele fica sem papéis.
    private static string NormalizeLogin(string username, string attribute)
    {
        var value = username.Trim();
        if (!string.Equals(attribute, "sAMAccountName", StringComparison.OrdinalIgnoreCase)) return value;
        var slash = value.LastIndexOf('\\');
        if (slash >= 0) value = value[(slash + 1)..];
        var at = value.IndexOf('@');
        return at > 0 ? value[..at] : value;
    }

    private static string EscapeFilterValue(string value) => value.Replace("\\", "\\5c", StringComparison.Ordinal).Replace("*", "\\2a", StringComparison.Ordinal).Replace("(", "\\28", StringComparison.Ordinal).Replace(")", "\\29", StringComparison.Ordinal).Replace("\0", "\\00", StringComparison.Ordinal);

    public bool ChangePassword(string username, string currentPassword, string newPassword, string bindPassword, LdapSettings settings)
    {
        var userId = FormatUserId(username, settings.UserIdFormat);
        if (userId is null || string.IsNullOrWhiteSpace(settings.BaseDn) || string.IsNullOrWhiteSpace(settings.BindUser)) return false;
        var attribute = Regex.IsMatch(settings.LoginAttribute, "^[A-Za-z][A-Za-z0-9-]{0,79}$") ? settings.LoginAttribute : "sAMAccountName";
        var hosts = new[] { settings.PrimaryHost, settings.SecondaryHost }.Where(h => !string.IsNullOrWhiteSpace(h)).Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var host in hosts)
        {
            try
            {
                var identifier = new LdapDirectoryIdentifier(host!, settings.Port, false, false);
                using var lookup = new LdapConnection(identifier, new NetworkCredential(settings.BindUser, bindPassword), AuthType.Basic) { Timeout = TimeSpan.FromSeconds(5) };
                lookup.SessionOptions.ProtocolVersion = 3; lookup.SessionOptions.ReferralChasing = ReferralChasingOptions.None; lookup.SessionOptions.SecureSocketLayer = true; lookup.Bind();
                var safeName = username.Trim().Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29").Replace("\0", "\\00");
                var search = new SearchRequest(settings.BaseDn, $"({attribute}={safeName})", SearchScope.Subtree, "distinguishedName");
                var response = (SearchResponse)lookup.SendRequest(search);
                if (response.Entries.Count != 1) return false;
                var dn = response.Entries[0].DistinguishedName;
                using var user = new LdapConnection(identifier, new NetworkCredential(userId, currentPassword), AuthType.Basic) { Timeout = TimeSpan.FromSeconds(5) };
                user.SessionOptions.ProtocolVersion = 3; user.SessionOptions.ReferralChasing = ReferralChasingOptions.None; user.SessionOptions.SecureSocketLayer = true; user.Bind();
                var oldValue = Encoding.Unicode.GetBytes($"\"{currentPassword}\"");
                var newValue = Encoding.Unicode.GetBytes($"\"{newPassword}\"");
                var change = new ModifyRequest(dn, DirectoryAttributeOperation.Delete, "unicodePwd", oldValue);
                var addNewPassword = new DirectoryAttributeModification { Name = "unicodePwd", Operation = DirectoryAttributeOperation.Add };
                addNewPassword.Add(newValue);
                change.Modifications.Add(addNewPassword);
                user.SendRequest(change);
                return true;
            }
            catch (LdapException ex) when (ex.ErrorCode == 49) { return false; }
            catch (Exception ex) when (ex is LdapException or DirectoryOperationException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException)
            { logger.LogWarning(ex, "Password change could not be completed through configured LDAPS endpoint {LdapHost}.", host); }
        }
        return false;
    }
}
