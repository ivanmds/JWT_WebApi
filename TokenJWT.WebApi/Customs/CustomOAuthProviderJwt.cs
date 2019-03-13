using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace TokenJWT.WebApi.Customs
{
    public class CustomOAuthProviderJwt : OAuthAuthorizationServerProvider
    {
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
            //FAKE FAZER A VALIDAÇÃO NO BANCO DE DADOS
            if (context.UserName != context.Password)
            {
                context.SetError("invalid_grant", "Usuário ou senha invalidos");
                return Task.FromResult<object>(null);
            }
            var identity = new ClaimsIdentity("JWT");
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            identity.AddClaim(new Claim("sub", context.UserName));
            identity.AddClaim(new Claim(ClaimTypes.Role, "Administrator")); //PEGAR AS ROLES CORRETAS
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