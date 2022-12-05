using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace API.Services
{
    public class TokenService : ITokenService
    {
        // Symmetric and AsymetricKey
        // Symetric key encrypts and decrupts the data, Server is responsible assigns token (token Key is encrypted) and decrypts the token
        // Asymetric Key (Server Encrypts - Client Decrypts) {public Key Decrypts private key Encrypts and stay on Server}
        private readonly SymmetricSecurityKey _key;
        public TokenService(IConfiguration config)
        {
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["TokenKey"]));// encode security key coming from config
        }
        public string CreateToken(AppUser user)
        {
            //Configure token
            //Create Claims
            var claims = new List<Claim>{// user JwtRegisteredClaimNames coming from system.identitymodel
                new Claim(JwtRegisteredClaimNames.NameId, user.UserName)//claim about a user, can have list of claims
            };

            // creating Signing Credentials with Key and Security Algorithm
            var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescriptor = new SecurityTokenDescriptor{
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(7),// expires in 7 days, need to login again after 7 days
                SigningCredentials = creds
            };
            //Create Token
            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}