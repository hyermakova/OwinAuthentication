﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Newtonsoft.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using SecurityCore.Entities;

namespace SecurityCore.Repositories
{
    public class UserRepository :
        IUserStore<User, string>,
        IUserPasswordStore<User, string>,
        IUserLockoutStore<User, string>,
        IUserTwoFactorStore<User, string>,
        IUserRoleStore<User, string>,
        IUserClaimStore<User, string>,
        IUserLoginStore<User, string>,
        IUserEmailStore<User, string>
    {
        private readonly string FolderStorage = string.Empty;
        private readonly Biggy.Data.Json.JsonStore<User> UserDb = null;
        private readonly Biggy.Data.Json.JsonStore<Role> RoleDb = null;

        public UserRepository(string folderStorage)
        {
            this.FolderStorage = folderStorage;
            this.UserDb = new Biggy.Data.Json.JsonStore<User>(this.FolderStorage, "Indentity", "Users");
            this.RoleDb = new Biggy.Data.Json.JsonStore<Role>(this.FolderStorage, "Indentity", "Roles");
        }

        #region USER STORE

        public System.Threading.Tasks.Task CreateAsync(User user)
        {
            user.Id = Guid.NewGuid().ToString();

            this.UserDb.Add(user);
            return Task.FromResult(user);
        }

        public System.Threading.Tasks.Task DeleteAsync(User user)
        {
            throw new NotImplementedException();
        }

        public System.Threading.Tasks.Task<User> FindByIdAsync(string userId)
        {
            User user = null;
            IList<User> users = this.UserDb.TryLoadData();
            if (users == null || users.Count == 0)
            {
                return Task.FromResult(user);
            }

            user = users.Where(f => f.Id == userId).SingleOrDefault();

            return Task.FromResult(user);
        }

        public System.Threading.Tasks.Task<User> FindByNameAsync(string userName)
        {
            User user = null;
            IList<User> users = this.UserDb.TryLoadData();
            if (users == null || users.Count == 0)
            {
                return Task.FromResult(user);
            }

            user = users.Where(f => f.UserName == userName).SingleOrDefault();

            return Task.FromResult(user);
        }



        public System.Threading.Tasks.Task UpdateAsync(User user)
        {
            return Task.FromResult(this.UserDb.Update(user));
        }

        public void Dispose()
        {
            this.UserDb.FlushToDisk();
        }

        #endregion

        #region PASSWORD STORE

        public System.Threading.Tasks.Task<string> GetPasswordHashAsync(User user)
        {
            return Task.FromResult(user.PasswordHash);
        }

        public System.Threading.Tasks.Task<bool> HasPasswordAsync(User user)
        {
            throw new NotImplementedException();
        }

        public System.Threading.Tasks.Task SetPasswordHashAsync(User user, string passwordHash)
        {
            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        #endregion

        #region LOCKOUT STORE

        public Task<int> GetAccessFailedCountAsync(User user)
        {
            return Task.FromResult(0);
        }

        public Task<bool> GetLockoutEnabledAsync(User user)
        {
            return Task.FromResult(user.LockoutEnabled);
        }

        public Task<DateTimeOffset> GetLockoutEndDateAsync(User user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            //if (!user.LockoutEndDateUtc.HasValue)
            //{ 
            //    throw new InvalidOperationException("LockoutEndDate has no value."); 
            //}

            return Task.FromResult(new DateTimeOffset(DateTime.Now.AddDays(-2)));
        }

        public Task<int> IncrementAccessFailedCountAsync(User user)
        {
            user.AccessFailedCount++;
            return Task.FromResult(0);
        }

        public Task ResetAccessFailedCountAsync(User user)
        {
            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }

        public Task SetLockoutEnabledAsync(User user, bool enabled)
        {
            user.LockoutEnabled = enabled;
            return Task.FromResult(0);
        }

        public Task SetLockoutEndDateAsync(User user, DateTimeOffset lockoutEnd)
        {
            user.LockoutEndDateUtc = lockoutEnd.DateTime;
            return Task.FromResult(0);
        }

        #endregion

        #region TWO FACTOR

        public Task<bool> GetTwoFactorEnabledAsync(User user)
        {
            return Task.FromResult(user.TwoFactorEnabled);
        }

        public Task SetTwoFactorEnabledAsync(User user, bool enabled)
        {
            user.TwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        #endregion

        #region USERS - ROLES STORE

        public Task AddToRoleAsync(User user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (string.IsNullOrEmpty(roleName))
            {
                throw new ArgumentNullException("role");
            }

            var roles = RoleDb.TryLoadData();
            var role = roles.Where(f => f.Name == roleName).SingleOrDefault();

            if (role == null)
            {
                throw new KeyNotFoundException("role");
            }

            if (role != null && user.Roles != null && !user.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase))
            {
                user.Roles.Add(roleName);
            }

            return Task.FromResult(0);
        }

        public Task<IList<string>> GetRolesAsync(User user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult<IList<string>>(user.Roles);
        }

        public Task<bool> IsInRoleAsync(User user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (string.IsNullOrEmpty(roleName))
            {
                throw new ArgumentNullException("role");
            }

            return Task.FromResult(user.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase));
        }

        public Task RemoveFromRoleAsync(User user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            user.Roles.Remove(roleName);

            return Task.FromResult(0);
        }

        #endregion

        #region USERS - CLAIM STORE

        public Task AddClaimAsync(User user, System.Security.Claims.Claim claim)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }

            if (user.Claims != null && user.Claims.Where(f => f.Value == claim.Value).Count() == 0)
            {
                user.Claims.Add(new UserClaim(claim));
            }

            return Task.FromResult(0);
        }

        public Task<IList<System.Security.Claims.Claim>> GetClaimsAsync(User user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return Task.FromResult<IList<System.Security.Claims.Claim>>(user.Claims.Select(clm => new System.Security.Claims.Claim(clm.Type, clm.Value)).ToList());
        }

        public Task RemoveClaimAsync(User user, System.Security.Claims.Claim claim)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (claim == null)
            {
                throw new ArgumentNullException("user");
            }

            user.Claims.Remove(new UserClaim(claim));

            return Task.FromResult(0);
        }

        #endregion

        #region USER - LOGINS

        public Task AddLoginAsync(User user, UserLoginInfo login)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (login == null)
            {
                throw new ArgumentNullException("user");
            }

            if (!user.Logins.Any(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey))
            {
                user.Logins.Add(new UserLoginInfo(login.LoginProvider, login.ProviderKey));
                UserDb.Update(user);
            }

            return Task.FromResult(true);
        }

        public Task<User> FindAsync(UserLoginInfo login)
        {
            var users = UserDb.TryLoadData();
            foreach (var user in users)
            {
                if (user.Logins.Any(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey))
                {
                    return Task.FromResult(user);
                }
            }
            string loginId = GetLoginId(login);
            //var user = UserDb.TryLoadData().Where(f => f.Id == loginId).SingleOrDefault();
            return Task.FromResult((User)null);
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(User user)
        {
            var logins = user.Logins;
            return Task.FromResult<IList<UserLoginInfo>>(logins);
        }

        public Task RemoveLoginAsync(User user, UserLoginInfo login)
        {
            user.Logins.Remove(login);
            return Task.FromResult(0);
        }

        #endregion

        #region SEND EMAIL STORE

        public Task<User> FindByEmailAsync(string email)
        {
            User user = null;
            IList<User> users = this.UserDb.TryLoadData();
            if (users == null || users.Count == 0)
            {
                return Task.FromResult(user);
            }

            user = users.Where(f => f.Email == email).SingleOrDefault();

            return Task.FromResult(user);
        }

        public Task<string> GetEmailAsync(User user)
        {
            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(User user)
        {
            return Task.FromResult(user.EmailConfirmed);
        }

        public Task SetEmailAsync(User user, string email)
        {
            user.Email = email;
            //this.UserDb.Update(user);
            return Task.FromResult(0);
        }

        public Task SetEmailConfirmedAsync(User user, bool confirmed)
        {
            user.EmailConfirmed = confirmed;
            //this.UserDb.Update(user);
            return Task.FromResult(0);
        }

        #endregion

        private string GetLoginId(UserLoginInfo login)
        {
            using (var sha = new SHA1CryptoServiceProvider())
            {
                byte[] clearBytes = Encoding.UTF8.GetBytes(login.LoginProvider + "|" + login.ProviderKey);
                byte[] hashBytes = sha.ComputeHash(clearBytes);
                return ToHex(hashBytes);
            }
        }

        private string ToHex(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
                sb.Append(bytes[i].ToString("x2"));
            return sb.ToString();
        }
    }
}
