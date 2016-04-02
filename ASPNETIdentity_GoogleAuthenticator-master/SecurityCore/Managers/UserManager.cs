using Microsoft.AspNet.Identity;
using System.Linq;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SecurityCore.Entities;
using SecurityCore.Repositories;
using SecurityCore.Services;
using SecurityCore.Providers;

namespace SecurityCore.Managers
{
    public class UserManager : UserManager<User, string>
    {
        static string folderStorage = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "_Storage");

        public UserManager(IUserStore<User, string> store)
            : base(store)
        {
        }

        public static UserManager Create(IdentityFactoryOptions<UserManager> options, IOwinContext context)
        {
            var manager = new UserManager(new UserRepository(folderStorage));
            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<User>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };
            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = false,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
            };
            // Configure user lockout defaults
            manager.UserLockoutEnabledByDefault = true;
            manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            manager.MaxFailedAccessAttemptsBeforeLockout = 5;
            
            manager.RegisterTwoFactorProvider("EmailCode", new EmailTokenProvider<User>
            {
                Subject = "SecurityCode",
                BodyFormat = "Your security code is {0}"
            });
            manager.RegisterTwoFactorProvider("GoogleAuthenticator", new GoogleAuthenticatorTokenProvider());

            /// TODO services
            manager.EmailService = new EmailService();
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider = new DataProtectorTokenProvider<User>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }

        /// <summary>
        /// Method to add user to multiple roles
        /// </summary>
        /// <param name="userId">user id</param>
        /// <param name="roles">list of role names</param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> AddUserToRolesAsync(string userId, IList<string> roles)
        {
            var userRoleStore = (IUserRoleStore<User, string>)Store;

            var user = await FindByIdAsync(userId).ConfigureAwait(false);
            if (user == null)
            {
                throw new InvalidOperationException("Invalid user Id");
            }

            var userRoles = await userRoleStore.GetRolesAsync(user).ConfigureAwait(false);
            // Add user to each role using UserRoleStore
            foreach (var role in roles.Where(role => !userRoles.Contains(role)))
            {
                await userRoleStore.AddToRoleAsync(user, role).ConfigureAwait(false);
            }

            // Call update once when all roles are added
            return await UpdateAsync(user).ConfigureAwait(false);
        }

        /// <summary>
        /// Remove user from multiple roles
        /// </summary>
        /// <param name="userId">user id</param>
        /// <param name="roles">list of role names</param>
        /// <returns></returns>
        public virtual async Task<IdentityResult> RemoveUserFromRolesAsync(string userId, IList<string> roles)
        {
            var userRoleStore = (IUserRoleStore<User, string>)Store;

            var user = await FindByIdAsync(userId).ConfigureAwait(false);
            if (user == null)
            {
                throw new InvalidOperationException("Invalid user Id");
            }

            var userRoles = await userRoleStore.GetRolesAsync(user).ConfigureAwait(false);
            // Remove user to each role using UserRoleStore
            foreach (var role in roles.Where(userRoles.Contains))
            {
                await userRoleStore.RemoveFromRoleAsync(user, role).ConfigureAwait(false);
            }

            // Call update once when all roles are removed
            return await UpdateAsync(user).ConfigureAwait(false);
        }

        public override async Task<IdentityResult> RemoveLoginAsync(string userId, UserLoginInfo login)
        {
            var user = await FindByIdAsync(userId).ConfigureAwait(false);
            if (user == null)
            {
                throw new InvalidOperationException("Invalid user Id");
            }

            user.Logins.RemoveAll(l => l.LoginProvider == login.LoginProvider && l.ProviderKey == login.ProviderKey);

            await UpdateAsync(user).ConfigureAwait(false);

            return await Task.FromResult(IdentityResult.Success);

        }
        //public override Task<ClaimsIdentity> CreateIdentityAsync(User user, string authenticationType)
        //{
        //    if (user == null)
        //    {
        //        throw new ArgumentNullException("user");
        //    }
        //    ClaimsIdentity claimsIdentity = new ClaimsIdentity(authenticationType, ClaimTypes.Name, ClaimTypes.Role);
        //    claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id, "http://www.w3.org/2001/XMLSchema#string"));
        //    claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, user.UserName, "http://www.w3.org/2001/XMLSchema#string"));
        //    claimsIdentity.AddClaim(new Claim("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider", "ASP.NET Identity", "http://www.w3.org/2001/XMLSchema#string"));
        //    if (SupportsUserSecurityStamp)
        //    {
        //        //claimsIdentity.AddClaim(new Claim(ClaimTypes., await manager.GetSecurityStampAsync(user.Id).WithCurrentCulture<string>()));
        //    }
        //    if (SupportsUserRole)
        //    {
        //        IList<string> list = ((UserRepository)Store).GetRolesAsync(user).Result;
        //        foreach (string current in list)
        //        {
        //            claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, current, "http://www.w3.org/2001/XMLSchema#string"));
        //        }
        //    }
        //    if (SupportsUserClaim)
        //    {
        //        claimsIdentity.AddClaims(((UserRepository)Store).GetClaimsAsync(user).Result);
        //    }
        //    return Task.FromResult(claimsIdentity);
        //}

    }
}
