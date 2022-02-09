using Authentication.Models;
using System.Threading.Tasks;

namespace Authentication.Interfaces
{
    public interface IUserServiceRepository
    {
		Task<bool> IsValidUserAsync(User user);

		UserRefreshToken AddUserRefreshTokens(UserRefreshToken user);

		UserRefreshToken GetSavedRefreshTokens(string username, string refreshtoken);

		void DeleteUserRefreshTokens(string username, string refreshToken);

		int SaveCommit();
	}
}
