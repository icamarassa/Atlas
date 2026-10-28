using System.Security.Cryptography;

namespace AtlasTi.Api;

public sealed record StoredDocumentFile(string StorageUri, string OriginalFileName, string ContentType, long Size, byte[] Sha256);

public sealed class DocumentFileStore(IConfiguration configuration, IWebHostEnvironment environment)
{
    public const long MaximumFileSize = 25 * 1024 * 1024;
    private readonly string _root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configuration["DocumentFiles:RootPath"]
        ?? Path.Combine(environment.ContentRootPath, "App_Data", "documents")));

    public async Task<StoredDocumentFile> SaveAsync(IFormFile file, CancellationToken cancellationToken)
    {
        if (file.Length <= 0 || file.Length > MaximumFileSize)
            throw new InvalidDataException("O arquivo precisa ter entre 1 byte e 25 MB.");

        var originalName = Path.GetFileName(file.FileName).Trim();
        if (string.IsNullOrWhiteSpace(originalName) || originalName.Length > 255)
            throw new InvalidDataException("Nome do arquivo inválido ou maior que 255 caracteres.");

        var extension = Path.GetExtension(originalName).ToLowerInvariant();
        var contentType = extension switch
        {
            ".pdf" => "application/pdf",
            ".doc" => "application/msword",
            ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            _ => throw new InvalidDataException("São aceitos somente arquivos PDF, DOC ou DOCX.")
        };

        await using var input = file.OpenReadStream();
        var signature = new byte[8];
        var read = await input.ReadAsync(signature.AsMemory(0, signature.Length), cancellationToken);
        var validSignature = extension switch
        {
            ".pdf" => read >= 5 && signature.AsSpan(0, 5).SequenceEqual("%PDF-"u8),
            ".doc" => read >= 8 && signature.AsSpan(0, 8).SequenceEqual(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }),
            ".docx" => read >= 4 && signature[0] == 0x50 && signature[1] == 0x4B && signature[2] == 0x03 && signature[3] == 0x04,
            _ => false
        };
        if (!validSignature) throw new InvalidDataException("O conteúdo do arquivo não corresponde à extensão informada.");
        input.Position = 0;

        Directory.CreateDirectory(_root);
        var storageUri = $"{Guid.NewGuid():N}{extension}";
        var target = Resolve(storageUri);
        await using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous | FileOptions.SequentialScan))
            await input.CopyToAsync(output, cancellationToken);

        await using var hashStream = File.OpenRead(target);
        var hash = await SHA256.HashDataAsync(hashStream, cancellationToken);
        return new StoredDocumentFile(storageUri, originalName, contentType, file.Length, hash);
    }

    public string Resolve(string storageUri)
    {
        if (string.IsNullOrWhiteSpace(storageUri) || Path.GetFileName(storageUri) != storageUri)
            throw new InvalidDataException("Caminho de arquivo inválido.");
        var path = Path.GetFullPath(Path.Combine(_root, storageUri));
        if (!path.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Caminho de arquivo fora da área permitida.");
        return path;
    }

    public void Delete(string storageUri)
    {
        var path = Resolve(storageUri);
        if (File.Exists(path)) File.Delete(path);
    }
}
