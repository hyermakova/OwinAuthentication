using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using IdentitySample.Models;
using Owin;
using System;
using System.Configuration;
using System.Threading.Tasks;
using Owin.Security.Providers;
using Microsoft.Owin.Security.WsFederation;
using SecurityCore.Managers;
using SecurityCore.Entities;
using Microsoft.Owin.Security.Google;
using Owin.Security.Providers.LinkedIn;
using Owin.Security.Providers.GitHub;

namespace IdentitySample {
    public partial class Startup {

        const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app) {
            // Configure the db context, user manager and role manager to use a single instance per request
            app.CreatePerOwinContext<UserManager>(UserManager.Create);
            app.CreatePerOwinContext<RoleManager>(RoleManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<UserManager, User>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            /// Twitter : Create a new application
            // https://dev.twitter.com/apps
            if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings.Get("TwitterConsumerKey")))
            {
                var twitterOptions = new Microsoft.Owin.Security.Twitter.TwitterAuthenticationOptions
                {
                    ConsumerKey = ConfigurationManager.AppSettings.Get("TwitterConsumerKey"),
                    ConsumerSecret = ConfigurationManager.AppSettings.Get("TwitterConsumerSecret"),
                    BackchannelCertificateValidator = new Microsoft.Owin.Security.CertificateSubjectKeyIdentifierValidator(new[]
                    {
                        "A5EF0B11CEC04103A34A659048B21CE0572D7D47", // VeriSign Class 3 Secure Server CA - G2
                        "0D445C165344C1827E1D20AB25F40163D8BE79A5", // VeriSign Class 3 Secure Server CA - G3
                        "7FD365A7C2DDECBBF03009F34339FA02AF333133", // VeriSign Class 3 Public Primary Certification Authority - G5
                        "39A55D933676616E73A761DFA16A7E59CDE66FAD", // Symantec Class 3 Secure Server CA - G4
                        "‎add53f6680fe66e383cbac3e60922e3b4c412bed", // Symantec Class 3 EV SSL CA - G3
                        "4eb6d578499b1ccf5f581ead56be3d9b6744a5e5", // VeriSign Class 3 Primary CA - G5
                        "5168FF90AF0207753CCCD9656462A212B859723B", // DigiCert SHA2 High Assurance Server C‎A 
                        "B13EC36903F8BF4701D498261A0802EF63642BC3" // DigiCert High Assurance EV Root CA
                    }),
                    Provider = new Microsoft.Owin.Security.Twitter.TwitterAuthenticationProvider
                    {
                        OnAuthenticated = (context) =>
                        {
                            context.Identity.AddClaim(new System.Security.Claims.Claim("urn:twitter:access_token", context.AccessToken, XmlSchemaString, "Twitter"));
                            return Task.FromResult(0);
                        }
                    }
                };

                app.UseTwitterAuthentication(twitterOptions);
            }

            // Facebook : Create New App
            // https://developers.facebook.com/apps
            if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings.Get("FacebookAppId")))
            {
                var facebookOptions = new Microsoft.Owin.Security.Facebook.FacebookAuthenticationOptions
                {
                    AppId = ConfigurationManager.AppSettings.Get("FacebookAppId"),
                    AppSecret = ConfigurationManager.AppSettings.Get("FacebookAppSecret"),
                    Provider = new Microsoft.Owin.Security.Facebook.FacebookAuthenticationProvider
                    {
                        OnAuthenticated = (context) =>
                        {
                            context.Identity.AddClaim(new System.Security.Claims.Claim("urn:facebook:access_token", context.AccessToken, XmlSchemaString, "Facebook"));
                            foreach (var x in context.User)
                            {
                                var claimType = string.Format("urn:facebook:{0}", x.Key);
                                string claimValue = x.Value.ToString();
                                if (!context.Identity.HasClaim(claimType, claimValue))
                                    context.Identity.AddClaim(new System.Security.Claims.Claim(claimType, claimValue, XmlSchemaString, "Facebook"));

                            }
                            return Task.FromResult(0);
                        }
                    }
                };
                facebookOptions.Scope.Add("email");
                app.UseFacebookAuthentication(facebookOptions);
            }

            if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings.Get("GoogleClientId")))
            {
                var googleOAuth2AuthenticationOptions = new GoogleOAuth2AuthenticationOptions
                {
                    ClientId = ConfigurationManager.AppSettings.Get("GoogleClientId"),
                    ClientSecret = ConfigurationManager.AppSettings.Get("GoogleClientSecret"),
                    //CallbackPath = new PathString(""),///Account/ExternalGoogleLoginCallback

                    Provider = new GoogleOAuth2AuthenticationProvider()
                    {
                        OnAuthenticated = (context) =>
                        {
                            context.Identity.AddClaim(new System.Security.Claims.Claim("urn:google:access_token", context.AccessToken, XmlSchemaString, "Google"));

                            return Task.FromResult(0);
                        }
                    }
                };

                googleOAuth2AuthenticationOptions.Scope.Add("email");

                app.UseGoogleAuthentication(googleOAuth2AuthenticationOptions);
            }

            if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings.Get("LinkedInClientId")))
            {
                var linkedinOptions = new LinkedInAuthenticationOptions
                {
                    ClientId = ConfigurationManager.AppSettings.Get("LinkedInClientId"),
                    ClientSecret = ConfigurationManager.AppSettings.Get("LinkedInClientSecret"),
                    //CallbackPath = new PathString("/Account/ExternalLoginCallback"),
                    Provider = new LinkedInAuthenticationProvider()
                    {
                        OnAuthenticated = (context) =>
                        {
                            context.Identity.AddClaim(new System.Security.Claims.Claim("urn:linkedin:access_token", context.AccessToken, XmlSchemaString, "LinkedIn"));

                            return Task.FromResult(0);
                        }
                    }
                };

                app.UseLinkedInAuthentication(linkedinOptions);
            }

            if (!string.IsNullOrEmpty(ConfigurationManager.AppSettings.Get("GithubClientId")))
            {
                var gitHubOptions = new GitHubAuthenticationOptions
                {
                    ClientId = ConfigurationManager.AppSettings.Get("GithubClientId"),
                    ClientSecret = ConfigurationManager.AppSettings.Get("GithubClientSecret"),
                    //CallbackPath = new PathString("/Account/ExternalLoginCallback"),
                    Provider = new GitHubAuthenticationProvider()
                    {
                        OnAuthenticated = (context) =>
                        {
                            context.Identity.AddClaim(new System.Security.Claims.Claim("urn:github:access_token", context.AccessToken, XmlSchemaString, "GitHub"));

                            return Task.FromResult(0);
                        }
                    }
                };

                app.UseGitHubAuthentication(gitHubOptions);
            }
        }
    }
}