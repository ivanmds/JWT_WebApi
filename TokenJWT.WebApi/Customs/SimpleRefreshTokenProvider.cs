using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace TokenJWT.WebApi.Customs
{
    public class SimpleRefreshTokenProvider : IAuthenticationTokenProvider
    {
        private static ConcurrentDictionary<string, AuthenticationTicket> _refreshTokens = new ConcurrentDictionary<string, AuthenticationTicket>();

        public void Create(AuthenticationTokenCreateContext context)
        {
            var guid = Guid.NewGuid().ToString();

            // maybe only create a handle the first time, then re-use

            _refreshTokens.TryAdd(guid, context.Ticket);

            // consider storing only the hash of the handle

            context.SetToken(guid);
        }

        public async Task CreateAsync(AuthenticationTokenCreateContext context)
        {

            var guid = Guid.NewGuid().ToString();
            
            // maybe only create a handle the first time, then re-use

            _refreshTokens.TryAdd(guid, context.Ticket);

            // consider storing only the hash of the handle

            context.SetToken(guid);
        }

        public void Receive(AuthenticationTokenReceiveContext context)
        {
            AuthenticationTicket ticket;

            if (_refreshTokens.TryRemove(context.Token, out ticket))
            {
                context.SetTicket(ticket);
            }
        }

        public async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            AuthenticationTicket ticket;

            if (_refreshTokens.TryRemove(context.Token, out ticket))
            {
                context.SetTicket(ticket);
            }
        }
    }
}