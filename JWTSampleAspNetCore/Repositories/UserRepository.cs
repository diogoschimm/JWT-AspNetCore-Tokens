using JWTSampleAspNetCore.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTSampleAspNetCore.Repositories
{
    public class UserRepository
    {
        private static readonly List<User> dbUsers = new List<User> {
            new User { Id = 1, Username = "diogo.rodrigo", Password = "123", Role = "manager" },
            new User { Id = 2, Username = "diogo.schimm", Password = "123", Role = "employee" }
        };

        public static User Get(string username, string password)
        {
            return dbUsers.FirstOrDefault(x => x.Username.ToLower() == username.ToLower() && x.Password == password);
        }

        public static User SaveRefreshToken(User usuario, string refreshToken)
        {
            var user = dbUsers.FirstOrDefault(u => u.Id == usuario.Id);
            user.RefreshToken = refreshToken;
            return user;
        }

        public static User GetRefreshToken(int userId, string refreshToken)
        {
            return dbUsers.FirstOrDefault(u => u.Id == userId && u.RefreshToken == refreshToken);
        }

        public static User Create(User user)
        {
            user.Id = dbUsers.Max(u => u.Id) + 1;
            dbUsers.Add(user);

            return user;
        }

    }
}
