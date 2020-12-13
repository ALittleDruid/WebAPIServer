using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using WebAPIServer.Helpers;
using WebAPIServer.Model;

namespace WebAPIServer.Services
{
    public interface IUserService
    {
        Task<User> AuthenticateAysnc(string username, string password);
        Task<List<User>> GetAllAysnc();
        Task<User> GetByIdAysnc(int id);
        Task<User> GetByNameAysnc(string name);
        Task<User> CreateAysnc(User user, string password);
        Task UpdateAysnc(User userParam, string password = null);
        Task DeleteAysnc(int id);
    }

    public class UserService : IUserService
    {
        private WebAPIDBContent _context;

        public UserService(WebAPIDBContent context)
        {
            _context = context;
        }

        public Task<User> AuthenticateAysnc(string username, string password)
        {
            return Task.Run(() =>
            {
                User user = null;
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    user = _context.Users.SingleOrDefault(x => x.UserName == username);
                }
                if (user != null && VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
                {
                    return user;
                }
                return null;
            });
        }

        public Task<User> CreateAysnc(User user, string password)
        {
            return Task.Run(() =>
            {
                if (string.IsNullOrWhiteSpace(password))
                {
                    throw new AppException("Password is required");
                }
                if (_context.Users.Any(x => x.UserName == user.UserName))
                {
                    throw new AppException("Username \"" + user.UserName + "\" is already taken");
                }
                CreatePasswordHash(password, out byte[] passwordHash, out byte[] passwordSalt);
                user.PasswordHash = passwordHash;
                user.PasswordSalt = passwordSalt;
                _context.Users.Add(user);
                _context.SaveChanges();
                return user;
            });
        }

        public Task DeleteAysnc(int id)
        {
            return Task.Run(() =>
            {
                var user = _context.Users.Find(id);
                if (user != null)
                {
                    _context.Users.Remove(user);
                    _context.SaveChanges();
                }
            });
        }

        public Task<List<User>> GetAllAysnc()
        {
            return Task.Run(_context.Users.ToList);
        }

        public Task<User> GetByIdAysnc(int id)
        {
            return Task.Run(() =>
            {
                return _context.Users.Find(id);
            });
        }

        public Task<User> GetByNameAysnc(string name)
        {
            return Task.Run(() =>
            {
                return _context.Users.FirstOrDefault(x => x.UserName == name);
            });
        }

        public Task UpdateAysnc(User userParam, string password = null)
        {
            return Task.Run(() =>
            {
                var user = _context.Users.Find(userParam.Id);
                if (user == null)
                {
                    throw new AppException("User not found");
                }
                if (userParam.UserName != user.UserName)
                {
                    if (_context.Users.Any(x => x.UserName == userParam.UserName))
                    {
                        throw new AppException("Username " + userParam.UserName + " is already taken");
                    }
                    user.UserName = userParam.UserName;
                }
                user.Phone = userParam.Phone;
                if (!string.IsNullOrWhiteSpace(password))
                {
                    CreatePasswordHash(password, out byte[] passwordHash, out byte[] passwordSalt);

                    user.PasswordHash = passwordHash;
                    user.PasswordSalt = passwordSalt;
                }
                _context.Users.Update(user);
                _context.SaveChanges();
            });
        }

        private static void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(password));
            }

            if (password.Length < 8)
            {
                throw new ArgumentException("The password should be at least 8 characters long.", nameof(password));
            }

            using var hmac = new HMACSHA512();
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        }

        private static bool VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt)
        {
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Value cannot be empty or whitespace only string.", nameof(password));
            }
            if (storedHash.Length != 64)
            {
                throw new ArgumentException("Invalid length of password hash (64 bytes expected).", nameof(storedHash));
            }
            if (storedSalt.Length != 128)
            {
                throw new ArgumentException("Invalid length of password salt (128 bytes expected).", nameof(storedSalt));
            }
            if (password.Length < 8)
            {
                throw new ArgumentException("The password should be at least 8 characters long.", nameof(password));
            }
            using (var hmac = new HMACSHA512(storedSalt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != storedHash[i])
                    {
                        return false;
                    }
                }
            }
            return true;
        }
    }
}
