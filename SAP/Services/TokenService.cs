using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace SecAuthProj {
    public class TokenService {
        private readonly string _key;
        private readonly string _issuer;
        private readonly string _audience;

        public TokenService(IConfiguration configuration) {
            _key = configuration.GetSection("JWT:Key").Value ?? throw new ArgumentException("JWT Key not configured");
            _issuer = configuration.GetSection("JWT:Issuer").Value ?? throw new ArgumentException("JWT Issuer not configured");
            _audience = configuration.GetSection("JWT:Audience").Value ?? throw new ArgumentException("JWT Audience not configured");
        }

        public string GenerateToken(string username, string role) {
            Claim[] claims = {
                new(JwtRegisteredClaimNames.Sub, username),
                new(ClaimTypes.Role, role),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            SymmetricSecurityKey key = new(System.Text.Encoding.UTF8.GetBytes(_key));
            SigningCredentials creds = new(key, SecurityAlgorithms.HmacSha256);

            JwtSecurityToken token = new(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                expires: DateTime.UtcNow.AddSeconds(30),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}