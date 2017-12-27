using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WeixinAuth.Demo.Data;
using WeixinAuth.Demo.Models;

namespace WeixinAuth.Demo.Data
{
    public class AppDbContext : IdentityDbContext<AppUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options)
            : base(options)
        {
        }


        /// <param name="builder"></param>
        /// <remarks>当此函数的实现发生改变时，需要执行以下命令才会修改数据库：
        /// <code>
        /// dotnet ef migrations add Xxx
        /// dotnet ef database update
        /// </code>
        /// </remarks>
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            // Customize the ASP.NET Identity model and override the defaults if needed.
            // For example, you can rename the ASP.NET Identity table names and more.
            // Add your customizations after calling base.OnModelCreating(builder);


        }
    }
}
