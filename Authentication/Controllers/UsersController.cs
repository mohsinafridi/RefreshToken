using Authentication.Interfaces;
using Authentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly IJWTManagerRepository _jWTManager;
        private readonly IUserServiceRepository _userServiceRepository;
        public UsersController(IJWTManagerRepository jWTManager, IUserServiceRepository userServiceRepository)
        {
            this._jWTManager = jWTManager;
            _userServiceRepository = userServiceRepository;
        }

        [HttpGet]
        public List<string> Get()
        {
            var users = new List<string>
        {
            "Mohsin Azam",
            "Abdul Basit",
            "Imran Khan"
        };
            return users;
        }
        [AllowAnonymous]
        [HttpPost]
        [Route("authenticateOld")]
        public IActionResult Authenticate(User usersdata)
        {
            var token = _jWTManager.Authenticate(usersdata);
            if (token == null)
            {
                return Unauthorized();
            }
            return Ok(token);
        }


        [AllowAnonymous]
        [HttpPost]
        [Route("authenticate")]
        public async Task<IActionResult> AuthenticateAsync(User usersdata)
        {
            var validUser = await _userServiceRepository.IsValidUserAsync(usersdata);

            if (!validUser)
            {
                return Unauthorized("Incorrect username or password!");
            }

            var token = _jWTManager.GenerateToken(usersdata.Name);

            if (token == null)
            {
                return Unauthorized("Invalid Attempt!");
            }

            // saving refresh token to the db
            UserRefreshToken obj = new UserRefreshToken
            {
                RefreshToken = token.RefreshToken,
                UserName = usersdata.Name
            };

            _userServiceRepository.AddUserRefreshTokens(obj);
            _userServiceRepository.SaveCommit();
            return Ok(token);
        }


        [AllowAnonymous]
        [HttpPost]
        [Route("refresh")]
        public IActionResult Refresh(Tokens token)
        {
            var principal = _jWTManager.GetPrincipalFromExpiredToken(token.AccessToken);
            var username = principal.Identity?.Name;

            //retrieve the saved refresh token from database
            var savedRefreshToken = _userServiceRepository.GetSavedRefreshTokens(username, token.RefreshToken);

            if (savedRefreshToken.RefreshToken != token.RefreshToken)
            {
                return Unauthorized("Invalid attempt!");
            }

            var newJwtToken = _jWTManager.GenerateRefreshToken(username);

            if (newJwtToken == null)
            {
                return Unauthorized("Invalid attempt!");
            }

            // saving refresh token to the db
            UserRefreshToken obj = new UserRefreshToken
            {
                RefreshToken = newJwtToken.RefreshToken,
                UserName = username
            };

            _userServiceRepository.DeleteUserRefreshTokens(username, token.RefreshToken);
            _userServiceRepository.AddUserRefreshTokens(obj);
            _userServiceRepository.SaveCommit();

            return Ok(newJwtToken);
        }
    }
}
