using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;

namespace aws_alb_oidc.owin
{


    public class ALBAuthenticationMiddleware : AuthenticationMiddleware<ALBAuthenticationOptions>
    {
        public ALBAuthenticationMiddleware(OwinMiddleware nextMiddleware, ALBAuthenticationOptions authOptions)
            : base(nextMiddleware, authOptions)
        { }

        protected override AuthenticationHandler<ALBAuthenticationOptions> CreateHandler()
        {
            return new ALBAuthenticationHandler();
        }
    }


    public class ALBAuthenticationOptions : AuthenticationOptions
    {
        public ALBAuthenticationOptions() : base("x-amzn-oidc-data")
        { }
    }

    public class ALBAuthenticationHandler : AuthenticationHandler<ALBAuthenticationOptions>
    {

     


        public ALBAuthenticationHandler()
        {
           
        }


        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {

            if (this.Request.Path.Value.StartsWith("/Health"))
            {
                return null;
            }


            AuthenticationProperties authProperties = new AuthenticationProperties();
            authProperties.IssuedUtc = DateTime.UtcNow;
            authProperties.ExpiresUtc = DateTime.UtcNow.AddMinutes(20);
            authProperties.AllowRefresh = true;
            authProperties.IsPersistent = false;

#if DEBUG
            string DEV_OIDC_USER = Environment.GetEnvironmentVariable("DEV_OIDC_USER");
            if (DEV_OIDC_USER != null)
            {
                IList<Claim> claimCollection = new List<Claim>
                {
                    new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "DEV_OIDC_USER"),
                    new Claim("client_id", DEV_OIDC_USER)
                };
                ClaimsIdentity claimsIdentity = new ClaimsIdentity(claimCollection, "Custom");
                AuthenticationTicket ticket = new AuthenticationTicket(claimsIdentity, authProperties);
                return ticket;
            }
#endif

            bool oidc_present = Request.Headers.TryGetValue("x-amzn-oidc-data", out string[] oidcData);
            if(oidc_present)
            {
                Utils.AuthResults rs = await Utils.IsAuthorised(oidcData[0]);
                if (rs.IsAuthorised)
                {
                    AuthenticationTicket ticket = new AuthenticationTicket(rs.ClaimsIdentity, authProperties);
                    return ticket;

                }
            }

            return null;
        }

    }
}