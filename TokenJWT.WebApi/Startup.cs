using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using TokenJWT.WebApi.Customs;

[assembly: OwinStartup(typeof(TokenJWT.WebApi.Startup))]
namespace TokenJWT.WebApi
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            OAuthAuthorizationServerOptions authServerOptions = new OAuthAuthorizationServerOptions()
            {
                //Em produção se atentar que devemos usar HTTPS
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/oauth2/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(30),
                Provider = new CustomOAuthProviderJwt(),
                RefreshTokenProvider = new SimpleRefreshTokenProvider(),
                AccessTokenFormat = new CustomJwtFormat("http://localhost")
            };

            app.UseOAuthAuthorizationServer(authServerOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions(){
                AccessTokenFormat = new CustomJwtFormat("http://localhost")
            });
        }
    }
}
