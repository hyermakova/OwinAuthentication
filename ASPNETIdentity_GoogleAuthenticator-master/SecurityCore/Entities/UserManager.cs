using System;
using System.Collections.Generic;
using System.Linq;

namespace Custom.Identity
{
    using System.Threading.Tasks;
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.Owin;
    using Microsoft.Owin;
    using System.Security.Claims;
    public class UserManager : UserManager<User, string>
    {
        IUserStore<User, string> store;

        public UserManager(IUserStore<User, string> store): base(store)
        {
            this.store = store;
            this.UserLockoutEnabledByDefault = false;
            // this.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(10);
            // this.MaxFailedAccessAttemptsBeforeLockout = 10;
            this.UserValidator = new UserValidator<User, string>(this)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = false
            };

            // Configure validation logic for passwords
            this.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 4,
                RequireNonLetterOrDigit = false,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
            };

        }

        public override Task<ClaimsIdentity> CreateIdentityAsync(User user, string authenticationType)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            ClaimsIdentity claimsIdentity = new ClaimsIdentity(authenticationType, ClaimTypes.Name, ClaimTypes.Role);
            claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id, "http://www.w3.org/2001/XMLSchema#string"));
            claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, user.UserName, "http://www.w3.org/2001/XMLSchema#string"));
            claimsIdentity.AddClaim(new Claim("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider", "ASP.NET Identity", "http://www.w3.org/2001/XMLSchema#string"));
            if (SupportsUserSecurityStamp)
            {
                //claimsIdentity.AddClaim(new Claim(ClaimTypes., await manager.GetSecurityStampAsync(user.Id).WithCurrentCulture<string>()));
            }
            if (SupportsUserRole)
            {
                IList<string> list = ((UserStore)store).GetRolesAsync(user).Result;
                foreach (string current in list)
                {
                    claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, current, "http://www.w3.org/2001/XMLSchema#string"));
                }
            }
            if (SupportsUserClaim)
            {
                claimsIdentity.AddClaims(((UserStore)store).GetClaimsAsync(user).Result);
            }
            return Task.FromResult(claimsIdentity);
        }
               
    }

    //public class MyUserManager: IDisposable {

    //    public MyUserManager() {
    //    }

    //    public static MyUserManager Create(IdentityFactoryOptions<MyUserManager> options,
    //    IOwinContext context) {
    //        return new MyUserManager();
    //    }

    //    #region IDisposable Support
    //    private bool disposedValue = false; // To detect redundant calls

    //    protected virtual void Dispose(bool disposing)
    //    {
    //        if (!disposedValue)
    //        {
    //            if (disposing)
    //            {
    //                // TODO: dispose managed state (managed objects).
    //            }

    //            // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
    //            // TODO: set large fields to null.

    //            disposedValue = true;
    //        }
    //    }

    //    // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
    //    // ~MyUserManager() {
    //    //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
    //    //   Dispose(false);
    //    // }

    //    // This code added to correctly implement the disposable pattern.
    //    public void Dispose()
    //    {
    //        // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
    //        Dispose(true);
    //        // TODO: uncomment the following line if the finalizer is overridden above.
    //        // GC.SuppressFinalize(this);
    //    }
    //    #endregion
    //}

}
