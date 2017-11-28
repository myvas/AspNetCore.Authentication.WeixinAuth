using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using AspNetCore.WeixinOAuth.Demo.Models;
using Microsoft.AspNetCore.Identity;

namespace Microsoft.AspNetCore.Identity.EntityFrameworkCore
{
    public class AppDbContext : IdentityDbContext<AppUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options)
            : base(options)
        {
        }

        /// <summary>
        /// Gets or sets the <see cref="DbSet{TEntity}"/> of User external logins.
        /// </summary>
        public DbSet<IdentityUserExternalLogin> UserExternalLogins { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            // Customize the ASP.NET Identity model and override the defaults if needed.
            // For example, you can rename the ASP.NET Identity table names and more.
            // Add your customizations after calling base.OnModelCreating(builder);

            builder.Entity<IdentityUserExternalLogin>(b =>
            {
                b.HasKey(r => r.CorrelationId);
                b.ToTable("AspNetUserExternalLogins");
            });
        }
    }
}
