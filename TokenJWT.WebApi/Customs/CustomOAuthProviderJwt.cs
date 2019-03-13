using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using TokenJWT.WebApi.Models;

namespace TokenJWT.WebApi.Customs
{
    public class CustomOAuthProviderJwt : OAuthAuthorizationServerProvider
    {
        private static IEnumerable<UserLogin> USERS = new UserLogin[] {
            new UserLogin("teste01", "111", new string[] { "adm", "t1" }),
            new UserLogin("teste02", "222", new string[] { "adm", "t2" }),
            new UserLogin("teste01", "333", new string[] { "adm", "t3" }),
        };

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId = string.Empty;
            string clientSecret = string.Empty;
            string symmetricKeyAsBase64 = string.Empty;
            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }
            if (context.ClientId == null)
            {
                context.SetError("invalid_clientId", "client_Id não pode ser nulo");
                return Task.FromResult<object>(null);
            }
            context.Validated();
            return Task.FromResult<object>(null);
        }

        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            UserLogin userLogin = USERS.FirstOrDefault(u => u.UserName == context.UserName && u.Password == context.Password);

            if (userLogin == null)
            {
                context.SetError("invalid_grant", "UserName and Password are invalids");
                context.Response.Headers.Add("StatusCode", new[] { ((int)HttpStatusCode.Unauthorized).ToString() });
                return Task.FromResult<object>(null);
            }
            var identity = new ClaimsIdentity("JWT");
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            identity.AddClaim(new Claim("sub", context.UserName));
            
            foreach(string claim in userLogin.Roles)
                identity.AddClaim(new Claim(ClaimTypes.Role, claim));

            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    {
                         "client_id", (context.ClientId == null) ? string.Empty : context.ClientId

                    }
                });

            var ticket = new AuthenticationTicket(identity, props);
            context.Validated(ticket);
            return Task.FromResult<object>(null);
        }


        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["client_id"];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
                return Task.FromResult<object>(null);
            }

            // Change auth ticket for refresh token requests
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);
            newIdentity.AddClaim(new Claim("newClaim", "newValue"));

            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);

            return Task.FromResult<object>(null);
        }
    }
}