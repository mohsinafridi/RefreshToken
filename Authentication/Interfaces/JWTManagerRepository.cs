using Authentication.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Authentication.Interfaces
{
    public class JWTManagerRepository : IJWTManagerRepository
    {
        Dictionary<string, string> UsersRecords = new Dictionary<string, string>
    {
        { "user1","password1"},
        { "user2","password2"},
        { "user3","password3"},
    };

        private readonly IConfiguration _configuration;
        public JWTManagerRepository(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public Models.Tokens Authenticate(User user)
        {
            if (!UsersRecords.Any(x => x.Key == user.Name && x.Value == user.Password))
            {
                return null;
            }

            // Else we generate JSON Web Token
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
              {
             new Claim(ClaimTypes.Name, user.Name)
              }),
                Expires = DateTime.UtcNow.AddMinutes(10),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return new Tokens { AccessToken = tokenHandler.WriteToken(token) };

        }

        public Tokens GenerateToken(string userName)
        {
            return GenerateJWTTokens(userName);
        }

        public Tokens GenerateRefreshToken(string userName)
        {
            return GenerateJWTTokens(userName);
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var Key = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Key),
                ClockSkew = TimeSpan.Zero
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            JwtSecurityToken jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }


            return principal;
        }

        public Tokens GenerateJWTTokens(string userName)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var tokenKey = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new Claim[]
                  {
                 new Claim(ClaimTypes.Name, userName)
                  }),
                    Expires = DateTime.Now.AddMinutes(1),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var refreshToken = GenerateRefreshToken();
                return new Tokens { AccessToken = tokenHandler.WriteToken(token), RefreshToken = refreshToken };
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

    }
}
