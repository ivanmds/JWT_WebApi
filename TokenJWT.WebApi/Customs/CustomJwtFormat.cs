using Microsoft.Owin.Security;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Linq;

namespace TokenJWT.WebApi.Customs
{
    public class CustomJwtFormat : ISecureDataFormat<AuthenticationTicket>
    {
        private readonly string _issuer = string.Empty;
        private readonly string _audience = string.Empty;
        private readonly string Base64Secret = "IxrAjDoa2FqElO7IhrSrUJELhUckePEPVpaePlS_Xaw";
        public CustomJwtFormat(string issuer)
        {
            _issuer = "http://localhost";
            _audience = "http://localhost";
        }

        public string Protect(AuthenticationTicket data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(Base64Secret));
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            var issued = data.Properties.IssuedUtc;
            var expires = data.Properties.ExpiresUtc;
            var token = new JwtSecurityToken(_issuer, _audience, data.Identity.Claims, issued.Value.UtcDateTime, expires.Value.UtcDateTime, signingCredentials);
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(token);
            return jwt;
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            try
            {
                var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(Base64Secret));
                var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                TokenValidationParameters validationParameters = new TokenValidationParameters()
                {
                    ValidIssuer = _issuer,
                    ValidAudience = _audience,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    LifetimeValidator = LifetimeValidator,
                    IssuerSigningKey = securityKey
                };

                SecurityToken token = null;
                var principal = handler.ValidateToken(protectedText, validationParameters, out token);
                var identity = principal.Identities;

                return new AuthenticationTicket(identity.First(), new AuthenticationProperties());
            }
            catch
            {
                return null;
            }
        }

        public bool LifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (expires != null)
            {
                if (DateTime.UtcNow < expires) return true;
            }
            return false;
        }
    }
}