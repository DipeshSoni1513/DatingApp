using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [Authorize]
    public class UsersController : BaseApiController
    {
        private readonly DataContext _context;
        public UsersController(DataContext context)
        {
            _context = context;
        }

        [AllowAnonymous]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<AppUser>>> GetUsers(){
            return await _context.Users.ToListAsync();
        } 
        
        
        [HttpGet("{id}")]
        public async Task<ActionResult<AppUser>> GetUserById(int id){
            // var user = _context.Users.Find(id);
            return await _context.Users.FindAsync(id);
        } 
    }
}