using Microsoft.EntityFrameworkCore;
using WebAPIServer.Model;

namespace WebAPIServer.Helpers
{
    public class WebAPIDBContent : DbContext
    {
        public WebAPIDBContent(DbContextOptions<WebAPIDBContent> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
    }
}
