using Authentication.Models;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.Interfaces
{
    public class UserServiceRepository : IUserServiceRepository
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppDbContext _db;

        public UserServiceRepository(UserManager<IdentityUser> userManager, AppDbContext db)
        {
            this._userManager = userManager;
            this._db = db;
        }
        public UserRefreshToken AddUserRefreshTokens(UserRefreshToken refreshToken)
        {
            _db.UserRefreshToken.Add(refreshToken);
            return refreshToken;
        }

        public void DeleteUserRefreshTokens(string username, string refreshToken)
        {
            var item = _db.UserRefreshToken.FirstOrDefault(x => x.UserName == username && x.RefreshToken == refreshToken);
            if (item != null)
            {
                _db.UserRefreshToken.Remove(item);
            }
        }

        public UserRefreshToken GetSavedRefreshTokens(string username, string refreshToken)
        {
            return _db.UserRefreshToken.FirstOrDefault(x => x.UserName == username && x.RefreshToken == refreshToken && x.IsActive == true);
        }

        public async Task<bool> IsValidUserAsync(User user)
        {
            var u = _userManager.Users.FirstOrDefault(o => o.UserName == user.Name);
            var result = await _userManager.CheckPasswordAsync(u, user.Password);
            return result;
        }

        public int SaveCommit()
        {
            return _db.SaveChanges();
        }
    }
}
