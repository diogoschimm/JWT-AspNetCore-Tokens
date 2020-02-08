using System;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using JWTSampleAspNetCore.Models;
using JWTSampleAspNetCore.Repositories;
using JWTSampleAspNetCore.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTSampleAspNetCore.Controllers
{
    [Route("v1/account")]
    [ApiController]
    public class HomeController : ControllerBase
    {
        [HttpPost]
        [Route("login")]
        [AllowAnonymous]
        public ActionResult<dynamic> Logar([FromBody]User model)
        {
            var user = UserRepository.Get(model.Username, model.Password);
            return GerarToken(user);
        }

        [HttpPost]
        [Route("refresh")]
        [AllowAnonymous]
        public ActionResult<dynamic> RefreshToken([FromBody]User model)
        {
            var user = UserRepository.GetRefreshToken(model.Id, model.RefreshToken);
            return GerarToken(user);
        }

        private ActionResult<dynamic> GerarToken(User user)
        {
            if (user == null)
                return NotFound(new { message = "Usuário ou senha inválidos" });

            var token = TokenService.GenerateToken(user);

            UserRepository.SaveRefreshToken(user, token.RefreshToken);

            return new {
                user = new {
                    user.Id,
                    user.Username,
                    user.Role
                },
                token
            };
        }

        [HttpGet]
        [Route("anonymous")]
        [AllowAnonymous]
        public string Anonymous() => "Anônimo";

        [HttpGet]
        [Route("authenticated")]
        [Authorize]
        public dynamic Authenticated()
        {
            var dados = User as ClaimsPrincipal;

            var roleClaim = dados.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role);
            var nomeClaim = dados.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name);
            var sidClaim = dados.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Sid);

            var nome = User.Identity.Name;
            var isAutenticado = User.Identity.IsAuthenticated;

            return new
            {
                id = sidClaim.Value,
                role = roleClaim.Value,
                nome = nomeClaim.Value,
                isAutenticado,
                nomeIdentity = nome
            };
        }

        [HttpPost]
        [Route("create")]
        [Authorize(Roles = "manager")]
        public User Create(User user) {
            return UserRepository.Create(user);
        } 

        [HttpGet]
        [Route("employee")]
        [Authorize(Roles = "employee,manager")]
        public string Employee() => "Funcionário";

        [HttpGet]
        [Route("manager")]
        [Authorize(Roles = "manager")]
        public string Manager() => "Gerente";
    }
}