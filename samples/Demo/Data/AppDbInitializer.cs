using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Demo.Models;

namespace Demo.Data
{
    public static class AppDbInitializer
    {
        public const string AdminUserName = "Admin";
        public const string AdminInitPassword = "P@ssw0rd";

        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            using (var db = new AppDbContext(serviceProvider.GetRequiredService<DbContextOptions<AppDbContext>>()))
            {
                await EnsureAdminUser(serviceProvider);
            }
        }

        private static async Task EnsureAdminUser(IServiceProvider serviceProvider)
        {
            var userManager = serviceProvider.GetRequiredService<UserManager<AppUser>>();

            var user = await userManager.FindByNameAsync(AdminUserName);
            if (user == null)
            {
                user = new AppUser()
                {
                    UserName = AdminUserName,
                    PhoneNumber = "13800138000",
                    PhoneNumberConfirmed = true,
                };
                var result = await userManager.CreateAsync(user, AdminInitPassword);
                if (!result.Succeeded)
                {
                    throw new Exception(GetErrorMessage(result));
                }
            }
        }

        private static string GetErrorMessage(IdentityResult identityResult)
        {
            var result = "";

            foreach (var error in identityResult.Errors)
            {
                result += $"[{error.Code}]{error.Description}" + Environment.NewLine;
            }
            return result;
        }


    }
}
