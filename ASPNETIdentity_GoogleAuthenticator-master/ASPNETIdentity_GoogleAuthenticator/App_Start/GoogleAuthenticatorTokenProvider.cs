using System;
using System.Globalization;
using System.Threading.Tasks;
using Base32;
using IdentitySample.Models;
using Microsoft.AspNet.Identity;
using OtpSharp;
using SecurityCore.Entities;

namespace ASPNETIdentity_GoogleAuthenticator
{
    //public class GoogleAuthenticatorTokenProvider : IUserTokenProvider<User, string>
    //{
    //    public Task<string> GenerateAsync(string purpose, UserManager<User, string> manager, User user)
    //    {
    //        return Task.FromResult((string)null);
    //    }

    //    public Task<bool> ValidateAsync(string purpose, string token, UserManager<User, string> manager, User user)
    //    {
    //        long timeStepMatched = 0;

    //        var otp = new Totp(Base32Encoder.Decode(user.GoogleAuthenticatorSecretKey));
    //        bool valid = otp.VerifyTotp(token, out timeStepMatched, new VerificationWindow(2, 2));

    //        return Task.FromResult(valid);
    //    }

    //    public Task NotifyAsync(string token, UserManager<User, string> manager, User user)
    //    {
    //        return Task.FromResult(true);
    //    }

    //    public Task<bool> IsValidProviderForUserAsync(UserManager<User, string> manager, User user)
    //    {
    //        return Task.FromResult(user.IsGoogleAuthenticatorEnabled);
    //    }
    //}
}