using System.Text;
using Authentication.API.Handlers;
using Authentication.Application.Abstracts;
using Authentication.Application.Services;
using Authentication.Domain.Entities;
using Authentication.Infrastructure;
using Authentication.Infrastructure.Options;
using Authentication.Infrastructure.Processors;
using Authentication.Infrastructure.Repositories;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using LoginRequest = Authentication.Domain.Requests.LoginRequest;
using RegisterRequest = Authentication.Domain.Requests.RegisterRequest;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services.Configure<JwtOptions>(
    builder.Configuration.GetSection(JwtOptions.JwtOptionsKey));

builder.Services.AddCors(opt =>
{
    opt.AddPolicy("CorsPolicy", options =>
    {
        options.AllowAnyHeader().AllowAnyMethod().AllowCredentials().WithOrigins("http://localhost:5173");
    });
});

builder.Services.AddIdentity<User, IdentityRole<Guid>>(opt =>
{
    opt.Password.RequireDigit = true;
    opt.Password.RequireLowercase = true;
    opt.Password.RequireNonAlphanumeric = true;
    opt.Password.RequireUppercase = true;
    opt.Password.RequiredLength = 8;
    opt.User.RequireUniqueEmail = true;
}).AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.AddDbContext<ApplicationDbContext>(opt =>
{
    opt.UseNpgsql(builder.Configuration.GetConnectionString("DbConnectionString"));
});

builder.Services.AddScoped<IAuthTokenProcessor, AuthTokenProcessor>();
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IAccountService, AccountService>();

builder.Services.AddAuthentication(opt =>
{
    opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    opt.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddCookie().AddGoogle(options =>
{
    var clientId = builder.Configuration["Authentication:Google:ClientId"];

    if (clientId == null)
    {
        throw new ArgumentNullException(nameof(clientId));
    }
    
    var clientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
    
    if (clientSecret == null)
    {
        throw new ArgumentNullException(nameof(clientSecret));
    }

    options.ClientId = clientId;
    options.ClientSecret = clientSecret;
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

}).AddJwtBearer(options =>
{
    var jwtOptions = builder.Configuration.GetSection(JwtOptions.JwtOptionsKey)
        .Get<JwtOptions>() ?? throw new ArgumentException(nameof(JwtOptions));

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtOptions.Issuer,
        ValidAudience = jwtOptions.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Secret))
    };

    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            context.Token = context.Request.Cookies["ACCESS_TOKEN"];
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization();

builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddHttpContextAccessor();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(opt =>
    {
        opt.WithTitle("JWT + Refresh Token Auth API");
    });
}

app.UseCors("CorsPolicy");

app.UseExceptionHandler(_ => { });
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/account/register", async (RegisterRequest registerRequest, IAccountService accountService) =>
{
    await accountService.RegisterAsync(registerRequest);

    return Results.Ok();
});

app.MapPost("/api/account/login", async (LoginRequest loginRequest, IAccountService accountService) =>
{
    await accountService.LoginAsync(loginRequest);

    return Results.Ok();
});

app.MapPost("/api/account/refresh", async (HttpContext httpContext, IAccountService accountService) =>
{
    var refreshToken = httpContext.Request.Cookies["REFRESH_TOKEN"];
    
    await accountService.RefreshTokenAsync(refreshToken);

    return Results.Ok();
});

app.MapGet("/api/account/login/google", ([FromQuery] string returnUrl, LinkGenerator linkGenerator,
    SignInManager<User> signManager, HttpContext context) =>
{
    var properties = signManager.ConfigureExternalAuthenticationProperties("Google",
        linkGenerator.GetPathByName(context, "GoogleLoginCallback")
        + $"?returnUrl={returnUrl}");

    return Results.Challenge(properties, ["Google"]);
});

app.MapGet("/api/account/login/google/callback", async ([FromQuery] string returnUrl,
    HttpContext context, IAccountService accountService) =>
{
    var result = await context.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);

    if (!result.Succeeded)
    {
        return Results.Unauthorized();
    }

    await accountService.LoginWithGoogleAsync(result.Principal);

    return Results.Redirect(returnUrl);

}).WithName("GoogleLoginCallback");

app.MapGet("/api/movies", () => Results.Ok(new List<string> { "Matrix" })).RequireAuthorization();

app.Run();