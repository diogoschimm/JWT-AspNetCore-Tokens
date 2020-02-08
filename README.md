# JWT-AspNetCore-Tokens
Exemplo de JWT com AspNetCore, tokens, refresh tokens, autenticação e autorização com roles

Link JWT: 
https://jwt.io/


## Dependências Nuget

```
Install-Package Microsoft.AspNetCore.Authentication
Install-Package Microsoft.AspNetCore.Authentication.JwtBearer
```

## Startup

Método ConfigureServices

```C#
  public void ConfigureServices(IServiceCollection services)
  {
      services.AddCors();
      services.AddControllers();

      var key = Encoding.ASCII.GetBytes(Settings.Secret);
      services.AddAuthentication(x =>
      {
          x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
          x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
      })
      .AddJwtBearer(x =>
      {
          x.RequireHttpsMetadata = false;
          x.SaveToken = true;
          x.TokenValidationParameters = new TokenValidationParameters
          {
              ValidateIssuerSigningKey = true,
              IssuerSigningKey = new SymmetricSecurityKey(key),
              ValidateIssuer = false,
              ValidateAudience = false
          };
      });
  }
```

Método Configure

```c#
  public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
  {
      if (env.IsDevelopment())
      {
          app.UseDeveloperExceptionPage();
      }

      app.UseRouting();
      app.UseCors(x => x
          .AllowAnyOrigin()
          .AllowAnyMethod()
          .AllowAnyHeader());

      app.UseAuthentication(); 
      app.UseAuthorization();

      app.UseEndpoints(endpoints =>
      {
          endpoints.MapControllers();
      });
  }
```

## Criando o Token (JWT)

```c#
  public static dynamic GenerateToken(User user)
  {
      var tokenHandler = new JwtSecurityTokenHandler();
      var key = Encoding.ASCII.GetBytes(Settings.Secret);
      var tokenDescriptor = new SecurityTokenDescriptor
      {
          Subject = new ClaimsIdentity(new Claim[]
          {
              new Claim(ClaimTypes.Name, user.Username.ToString()),
              new Claim(ClaimTypes.Role, user.Role.ToString()),
              new Claim(ClaimTypes.Sid, user.Id.ToString()),
          }),
          Expires = DateTime.UtcNow.AddHours(2),
          SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
      };
      var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);

      return new
      {
          tokenDescriptor.Expires,
          Token = tokenHandler.WriteToken(token),
          RefreshToken = Guid.NewGuid().ToString().ToLower()
      };
  }
```

## Api para Autenticar e para Refresh do Token

```c#
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
```

## Api para buscar dados autenticados e Api anônima

```c#
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
```

## Api para autorização por roles

```c#
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
```
