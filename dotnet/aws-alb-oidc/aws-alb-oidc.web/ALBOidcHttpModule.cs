using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace aws_alb_oidc.web
{
    public class ALBOidcHttpModule : IHttpModule
    {
        public void Dispose()
        {
            // Deliberately do nothing, unsubscribing from events is not
            // needed by the IIS model. Trying to do so throws exceptions.
        }
        public void Init(HttpApplication app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            var wrapper = new EventHandlerTaskAsyncHelper(DoAsyncWork);

            //app.AddOnPostMapRequestHandlerAsync(wrapper.BeginEventHandler, wrapper.EndEventHandler);
            app.AddOnAuthenticateRequestAsync(wrapper.BeginEventHandler, wrapper.EndEventHandler);
        }

        private async Task DoAsyncWork(object sender, EventArgs e)
        {
            var app = (HttpApplication)sender;
            var ctx = app.Context;
            IDictionary<string, string> log = null;

            if (ctx.User != null || ctx.User.Identity.IsAuthenticated)
            {
                return; //short circut on auth'd
            }
            try
            {
                //local dev path
                List<Claim> claimCollection = null;

#if DEBUG
                string DEV_OIDC_USER = Environment.GetEnvironmentVariable("DEV_OIDC_USER");
                if (DEV_OIDC_USER != null)
                {
                    claimCollection = new List<Claim>()
                    {
                        new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "DEV_OIDC_USER"),
                        new Claim("client_id", DEV_OIDC_USER)
                    };
                    CreateFederatedAuthentication(ctx, claimCollection);
                    return;
                }
#endif

                log = new Dictionary<string, string>();

                var oidc_header = ctx.Request.Headers.Get("x-amzn-oidc-data");
                if(oidc_header == null)
                {
                    log["validation"] = "Missing httpheader 'x-amzn-oidc-data'";
                    return;
                }

                var auth_rs = await aws_alb_oidc.Utils.IsAuthorised(oidc_header);
                if(!auth_rs.IsAuthorised)
                {
                    log["validation"] = "httpheader 'x-amzn-oidc-data' was invalid";
                    return;
                }

                claimCollection = new List<Claim>();
                //parse client_id from custom:upn
                //add to claims
                //concat to aother claims from JWT

                CreateFederatedAuthentication(ctx, claimCollection);
                return;


            }
            catch (Exception ex)
            {
                var ex_msg = $"OIDC Error ->\r\n{BuildDescriptionOfException(ex)}";
                System.Diagnostics.EventLog.WriteEntry("aws-alb-oidc", ex_msg, System.Diagnostics.EventLogEntryType.Error);
            }
            finally
            {
                try
                {
                    if (log != null && log.Keys.Count > 0)
                    {
                            System.Diagnostics.EventLog.WriteEntry("aws-alb-oidc", JsonConvert.SerializeObject(log), System.Diagnostics.EventLogEntryType.Information);
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.EventLog.WriteEntry("aws-alb-oidc", BuildDescriptionOfException(ex), System.Diagnostics.EventLogEntryType.Error);
                }

            }

        }

        private void CreateFederatedAuthentication(HttpContext ctx, IList<Claim> Claims)
        {
            var c_id = Claims.Where(q => q.Type == "client_id").FirstOrDefault();
            if (c_id == null)
            {
                throw new Exception("client_id is missing");
            }

            Claims.Add(new Claim(ClaimTypes.Role, "User"));

            //add log_out url to claims as ClaimTypes.UserData
            Claims.Add(new Claim(ClaimTypes.UserData, Utils.BuildLogoutUrl_v1(), ClaimValueTypes.String));


            ClaimsIdentity ci = new ClaimsIdentity(Claims, "aws-alb-oidc.web", ClaimTypes.Name, ClaimTypes.Role);
            ClaimsPrincipal principal = new ClaimsPrincipal(ci);
            ctx.User = principal;

            var sessionToken = new SessionSecurityToken(principal);

            FederatedAuthentication.SessionAuthenticationModule
                .AuthenticateSessionSecurityToken(sessionToken, true);
        }


        internal static string BuildDescriptionOfException(Exception e)
        {
            string description = "Source : " + e.Source;
            description += "\r\n" + "Message : " + e.Message;
            description += "\r\n" + "Stack   : " + e.StackTrace;
            if (e.InnerException != null)
            {
                description += "---------------------";
                description += "\r\nInner Exception: ";
                description += BuildDescriptionOfException(e.InnerException);
            }
            return description;
        }

    }

}