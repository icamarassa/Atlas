using MySqlConnector;

namespace AtlasTi.Api;

public sealed class DatabaseConnectionFactory(string connectionString)
{
    public MySqlConnection Create() => new(connectionString);

    public async Task<MySqlConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = Create();
        try
        {
            await connection.OpenAsync(cancellationToken);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }
}
