using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
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
using System.Configuration;
using System.Web;

namespace aws_alb_oidc
{
    public static class Utils
    {
        internal const string ALBPublicKeyUrlFormatString = "https://public-keys.auth.elb.{0}.amazonaws.com/{1}";
        private static JsonWebTokenHandler _TokenHandler = new JsonWebTokenHandler();
        private static  ConcurrentDictionary<string, TokenValidationParameters> _cachedValidationParameters = new ConcurrentDictionary<string, TokenValidationParameters>();
        private static HttpClient InternalHttpClient = new HttpClient();
        private static string _Region = Environment.GetEnvironmentVariable("AWS_REGION");

        public class AuthResults
        {
            public bool IsAuthorised;
            public ClaimsIdentity ClaimsIdentity;
        }

        public static async Task<AuthResults> IsAuthorised(string OIDC_Data)
        {
            ClaimsIdentity claimsIdentity = null;
            bool isAuthorised = false;

            var jwt = new JsonWebToken(OIDC_Data);
            if (!_cachedValidationParameters.TryGetValue(jwt.Kid, out TokenValidationParameters validationParameters))
            {
                var uri = string.Format(ALBPublicKeyUrlFormatString, _Region, jwt.Kid);
                var publicRsa = await InternalHttpClient.GetStringAsync(uri);

                validationParameters = new TokenValidationParameters
                {
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = ConvertPemToSecurityKey(publicRsa),
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(2)
                };

                _cachedValidationParameters.TryAdd(jwt.Kid, validationParameters);
            }

            TokenValidationResult validationResult = _TokenHandler.ValidateToken(jwt.EncodedToken, validationParameters);
            if (!validationResult.IsValid)
                throw validationResult.Exception;

            var upn = jwt.Claims.First(c => c.Type == "custom:upn");
            if (upn != null)
            {
                var splits = upn.Value.Split('@');
                if (splits.Length > 0)
                {
                    IList<Claim> claimCollection = new List<Claim>
                    {
                        new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", splits[0]),
                        new Claim("client_id", splits[0])
                    };
                    claimsIdentity = new ClaimsIdentity(claimCollection.Concat(jwt.Claims), "Custom");
                    isAuthorised = true;
                }
            }
            

            return new AuthResults
            {
                IsAuthorised = isAuthorised,
                ClaimsIdentity = claimsIdentity
            };
        }


        private static ECDsaSecurityKey ConvertPemToSecurityKey(string pem)
        {
            using (TextReader publicKeyTextReader = new StringReader(pem))
            {
                var ec = (ECPublicKeyParameters)new PemReader(publicKeyTextReader).ReadObject();
                var ecpar = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint
                    {
                        X = ec.Q.XCoord.GetEncoded(),
                        Y = ec.Q.YCoord.GetEncoded()
                    }
                };

                return new ECDsaSecurityKey(ECDsa.Create(ecpar));
            }
        }


        public static string BuildLogoutUrl_v1()
        { 

            var client_id = ConfigurationManager.AppSettings["OIDC_CLIENT_ID"];
            var logout_url = ConfigurationManager.AppSettings["OIDC_LOGOUT_URL"];
            var idp_logout_url = ConfigurationManager.AppSettings["OIDC_IDP_LOGOUT_URL"];

            return  $"{logout_url}?client_id={client_id}&logout_uri={HttpUtility.UrlEncode(idp_logout_url)}";
        }


    }

}
