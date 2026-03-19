using Microsoft.EntityFrameworkCore;

namespace WebVulnScanner.Core.Database;

public class AppDbContext : DbContext
{
    public DbSet<ScanEntity> Scans => Set<ScanEntity>();
    public DbSet<ProxyLogEntity> ProxyLogs => Set<ProxyLogEntity>();

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "WebVulnScanner",
            "scanner.db");

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        options.UseSqlite($"Data Source={path}");
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ScanEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.ResultsJson).HasColumnType("TEXT");
        });

        modelBuilder.Entity<ProxyLogEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.RawRequest).HasColumnType("TEXT");
        });
    }
}
