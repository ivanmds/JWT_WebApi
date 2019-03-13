using System.Collections.Generic;

namespace TokenJWT.WebApi.Models
{
    public class UserLogin
    {
        public UserLogin(string userName, string password, string[] roles)
        {
            UserName = userName;
            Password = password;
            Roles = roles;
        }

        public string UserName { get; private set; }
        public string Password { get; private set; }
        public IEnumerable<string> Roles { get; private set; }
    }
}