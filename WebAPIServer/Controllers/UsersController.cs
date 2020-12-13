using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using WebAPIServer.Dtos;
using WebAPIServer.Helpers;
using WebAPIServer.Model;
using WebAPIServer.Services;

namespace WebAPIServer.Controllers
{
    [Authorize(Roles = "Admin")]
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        public static JwtSecurityTokenHandler JwtTokenHandler = new JwtSecurityTokenHandler();
        public static SymmetricSecurityKey SecurityKey = new SymmetricSecurityKey(Guid.NewGuid().ToByteArray());

        private IUserService _userService;
        private IMapper _mapper;
        private IActionContextAccessor _accessor;
        private readonly ILogger<UsersController> _logger;


        public UsersController(
            ILogger<UsersController> logger,
            IUserService userService,
            IMapper mapper,
            IActionContextAccessor httpContextAccessor)
        {
            _logger = logger;
            _userService = userService;
            _mapper = mapper;
            _accessor = httpContextAccessor;
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate(UserDto userDto)
        {
            _logger.LogInformation($"Authenticate {userDto.Username}@{userDto.Password}");
            var user = await _userService.AuthenticateAysnc(userDto.Username, userDto.Password);

            if (user == null)
                return BadRequest(new { message = "Username or password is incorrect" });

            var claims = new[] { new Claim(ClaimTypes.Name, user.UserName), new Claim(ClaimTypes.Role, user.UserType.ToString()) };
            var credentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken("WebAPIServer", "WebAPIClients", claims, expires: DateTime.Now.AddDays(1), signingCredentials: credentials);
            var tokenString = JwtTokenHandler.WriteToken(token);
            return Ok(new
            {
                Type = "Bearer",
                Token = tokenString
            });
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register(UserDto userDto)
        {
            _logger.LogInformation($"Register {userDto.Username}@{userDto.Password}@{userDto.Phone}");
            var user = _mapper.Map<User>(userDto);
            try
            {
                var _user = await _userService.CreateAysnc(user, userDto.Password);
                return Ok(_mapper.Map<UserDto>(_user));
            }
            catch (AppException ex)
            {
                _logger.LogWarning($"Register AppException"+ ex.Message);
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            _logger.LogInformation($"GetAll");
            var users = await _userService.GetAllAysnc();
            var userDtos = _mapper.Map<List<UserDto>>(users);
            return Ok(userDtos);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetById(int id)
        {
            _logger.LogInformation($"GetById {id}");
            var user = await _userService.GetByIdAysnc(id);
            var userDto = _mapper.Map<UserDto>(user);
            return Ok(userDto);
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> Update(int id, UserDto userDto)
        {
            _logger.LogInformation($"Update {id} {userDto.Username}@{userDto.Password}@{userDto.Phone}");
            var user = _mapper.Map<User>(userDto);
            user.Id = id;
            try
            {
                await _userService.UpdateAysnc(user, userDto.Password);
                return Ok();
            }
            catch (AppException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(int id)
        {
            _logger.LogInformation($"Delete {id}");
            await _userService.DeleteAysnc(id);
            return Ok();
        }
    }
}
