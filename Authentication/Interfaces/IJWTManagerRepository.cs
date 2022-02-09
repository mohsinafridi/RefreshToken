using Authentication.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authentication.Interfaces
{
    public interface IJWTManagerRepository
    {
        Tokens Authenticate(User users);
        Tokens GenerateToken(string userName);
        Tokens GenerateRefreshToken(string userName);
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
